import requests
import json
import datetime
from requests.auth import HTTPBasicAuth
import azure.functions as func
import base64
import hmac
import hashlib
import os
import logging
import re
from .state_manager import StateManager

customer_id = os.environ['WorkspaceID']
shared_key = os.environ['WorkspaceKey']
auth_token = os.environ['MiroAccessToken']
connection_string = os.environ['AzureWebJobsStorage']
log_type = 'Miro_Auditlogs'
# v2 doesn't return size in response.
miro_api_url = "https://api.miro.com/v1/audit/logs"
logAnalyticsUri = os.environ.get('logAnalyticsUri')

if ((logAnalyticsUri in (None, '') or str(logAnalyticsUri).isspace())):
    logAnalyticsUri = 'https://' + customer_id + '.ods.opinsights.azure.com'

pattern = r"https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$"
match = re.match(pattern, str(logAnalyticsUri))
if (not match):
    raise Exception("Invalid Log Analytics Uri.")


def generate_date():
    current_time = datetime.datetime.utcnow().replace(second=0, microsecond=0) - \
        datetime.timedelta(minutes=10)
    state = StateManager(connection_string=connection_string)
    past_time = state.get()
    if past_time is not None:
        logging.info("The last time point is: {}".format(past_time))
    else:
        logging.info(
            "There is no last time point, trying to get events for last hour.")
        past_time = (current_time - datetime.timedelta(minutes=60)
                     ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    state.post(current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    return (past_time, current_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))


def get_result_request(offset, limit, from_time, to_time):
    try:
        # limits on miro api while using params in body
        api_url_params = miro_api_url + \
            f'?createdAfter={from_time}&createdBefore={to_time}&limit={limit}&offset={offset}'

        r = requests.get(url=api_url_params,
                         headers={'Authorization': f'Bearer {auth_token}'},
                         )
        if r.status_code == 200:
            logging.info("1. Miro API returned 200 OK")
            return r.json()
        elif r.status_code == 401:
            logging.error(
                "The authentication credentials are incorrect or missing. Error code: {}".format(r.status_code))
        elif r.status_code == 403:
            logging.error(
                "The user does not have the required permissions. Error code: {}".format(r.status_code))
        else:
            logging.error(
                "Something went wrong. Error code: {}".format(r.status_code))
    except Exception as err:
        logging.error(
            "Something went wrong. Exception error text: {}".format(err))


def get_result(time_range):
    from_time = time_range[0]
    to_time = time_range[1]
    offset = 0
    limit = 500
    collected_data = []  # List of total items fetched

    while True:
        result = get_result_request(offset, limit, from_time, to_time)
        data = result['data']
        data_count = len(data)
        data_total_count = result['size']
        collected_data_count = len(collected_data)

        if result is not None:
            if offset == 0 and data_count == 0:
                logging.info("Logs not found. Time period: from {} to {}.".format(
                    from_time, to_time))
            elif collected_data_count >= data_total_count:
                break
            elif data_count > 0:
                logging.info("Processing {} events".format(data_count))
                collected_data.extend(data)  # Add data to list

            offset += limit

        else:
            break

    if collected_data_count > 0:
        logging.info("2. Posting data to Sentinel")
        post_status_code = post_data(json.dumps(collected_data))
        if post_status_code is not None:
            logging.info("Posted {} out of {} events to Azure Sentinel. Time period: from {} to {}.".format(
                collected_data_count, data_total_count, from_time, to_time))
    else:
        logging.info("No events to process. Time period: from {} to {}.".format(
            from_time, to_time))


def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + \
        str(content_length) + "\n" + content_type + \
        "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(
        decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization


def post_data(body):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(
        customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = logAnalyticsUri + resource + "?api-version=2016-04-01"
    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    response = requests.post(uri, data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        return response.status_code
    else:
        logging.warn("Events are not processed into Azure. Response code: {}".format(
            response.status_code))
        return None


def main(mytimer: func.TimerRequest) -> None:
    if mytimer.past_due:
        logging.info('The timer is past due!')
    logging.info('Starting program')
    get_result(generate_date())
