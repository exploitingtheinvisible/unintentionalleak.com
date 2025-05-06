# Python 3.8+
# pip install -r requirements.txt
import json
import os
import pandas as pd
import base64
import random
import re
import requests
import socket
import sys
import time
import traceback

from datetime import datetime, timezone
from operator import itemgetter
from typing import Any
from yaspin import yaspin

start_time = datetime.now()


cloudsecurity_CONFIG_PATH = "cloudsecuritycreds.json"
CSV_FNAME = "cloudsecurity_ccrs"

MAX_QUERY_RETRIES = 5
BLUE = "\033[94m"
GREEN = "\033[92m"
END = "\033[0m"
SPINNER_COLORS = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]

SCRIPT_NAME = "Get cloudsecurity Cloud Configuration Rules (CCRs)"
SCRIPT_DESCRIPTION = f"{BLUE}DESCRIPTION:{END}\n  - This script will parse the cloudsecurity CCRs\n  - and write out to a CSV file"

class Timer:
    """
    A class to generate generic timer objects that we use to time function execution
    """

    def __init__(self, text: str):
        self.text = text
        self._start = datetime.now()

    def __str__(self) -> str:
        now = datetime.now()
        delta = now - self._start
        # split the time into minutes:seconds
        total_time = (
            f"{round(delta.total_seconds(),1)}"
            if delta.total_seconds() < 60
            # round rounds down by default, so we include a remainder in the calculation to force
            # a round up in the minutes calculation withouth having to include an additional library
            else f"{round((delta.total_seconds() // 60 + (delta.total_seconds() % 60 > 0)))}:{round((delta.total_seconds()% 60),1)}"
        )
        return f"{self.text} - Total elapsed time: {total_time}s"


class cloudsecurityClient:
    """
    A class to generate a cloudsecurity client thats handle auth and configuration parsing
    """

    def __init__(self, cloudsecurity_config_file: str) -> None:
        # Holds the token used for the api calls.
        # Set default socket timeout to 20 seconds
        socket.setdefaulttimeout(20)
        # Set blocking to prevent overrides of socket timeout
        # docs: https://docs.python.org/3/library/socket.html#socket-timeouts
        socket.socket.setblocking = self._set_socket_blocking()
        # Value of cloudsecurity_dc is set by _request_api_token function
        self.cloudsecurity_dc = ""
        # The headers and header auth formats sent with POST
        self.HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded"}
        self.HEADERS = {"Content-Type": "application/json"}
        # The path of the cloudsecurity config file
        self.auth_url, self.client_id, self.client_secret = self._config_parser(
            cloudsecurity_config=cloudsecurity_config_file
        )
        # Requests a cloudsecurity API token
        # And sets the cloudsecurity_dc by inferring the value from the token
        self._request_cloudsecurity_api_token(
            auth_url=self.auth_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )
        self.api_url = f"https://api.{self.cloudsecurity_dc}.app.cloudsecurity.io/graphql"

    # @_generic_exception_handler
    def _set_socket_blocking(self) -> Any:
        """
        Internal class method that Sets blocking for http sockets
        so that no other internal libs
        can overwrite the defalt socket timeout

        Parameters:
            - none

        Returns:
            - none
        """
        setblocking_func = socket.socket.setblocking

        def wrapper(self: Any, flag: Any) -> Any:
            if flag:
                # prohibit timeout reset
                timeout = socket.getdefaulttimeout()
                if timeout:
                    self.settimeout(timeout)
                else:
                    setblocking_func(self, flag)
            else:
                setblocking_func(self, flag)

        wrapper.__doc__ = setblocking_func.__doc__
        wrapper.__name__ = setblocking_func.__name__
        return wrapper

    def _pad_base64(self, data: Any) -> Any:
        """
        Internal class method that Ensures that base64 data is padded correctly

        Parameters:
            - data: the base64 data to pad if needed

        Returns:
            - padded: the padded base64 data
        """
        padded = data
        missing_padding = len(padded) % 4
        if missing_padding != 0:
            padded += "=" * (4 - missing_padding)
        return padded

    # @_generic_exception_handler
    def _validate_config(
        self, client_id: str, client_secret: str, auth_url: str
    ) -> None:
        """
        Internal class method that valides the inputs from the config parser
        And exit if any are not

        Parameters:
            - client_id: the cloudsecurity client id to check
            - client_secrete: the cloudsecurity client secret to check
            - auth_url: the cloudsecurity auth url to check

        Returns:
            - none

        """

        # Regex to match us1 - us28, and us28 - 36 (note the ranges we skip)
        auth0_client_matcher = "([a-zA-Z0-9]{32})"
        # 52 or 53 char alphanumeric match for cognito client ids
        cognito_client_matcher = "([a-zA-Z0-9]{52,53})"
        # 64 char alphanumeric match for secret
        secret_matcher = "([A-Za-z0-9-]{64})"

        cloudsecurity_auth_endpoints = [
            "https://auth.app.cloudsecurity.io/oauth/token"

        ]

        # check to make sure the api url is valid
        if auth_url not in cloudsecurity_auth_endpoints:
            sys.exit(
                f"[ERROR] {auth_url} is not a valid cloudsecurity Auth Endpoint. Please check your config file and try again. Exiting..."
            )
        # If we don't find a valid client ID, exit
        if not (
            re.fullmatch(auth0_client_matcher, client_id)
            or re.fullmatch(cognito_client_matcher, client_id)
        ):
            sys.exit(
                f"[ERROR] Did not find a valid cloudsecurity Client ID. Please check your config file and try again. Exiting..."
            )

        # If we dont' find a valid secret, exit
        if not re.fullmatch(secret_matcher, client_secret):
            sys.exit(
                f"[ERROR] Did not find a valid cloudsecurity Secret. Please check your config file and try again. Exiting..."
            )

    # @_generic_exception_handler
    def _config_parser(self, cloudsecurity_config: str) -> tuple:
        """
        Internal class method that parses the system for a config file
        OR environment variables for the script to use
        The default behavior is to try a config file first
        And then defer to environment variables

        Parameters:
            - none

        Returns:
            - cloudsecurity_CLIENT_ID: the cloudsecurity client id pulled from the config file or the local environment variables
            - cloudsecurity_CLIENT_SECRET: the cloudsecurity client secret pulled from the config file or the local environment variables
            - cloudsecurity_AUTH_URL: the cloudsecurity client id pulled from the config file or the local environment variables
        """

        try:
            with open(f"{cloudsecurity_config}", mode="r") as config_file:
                config = json.load(config_file)

                # Extract the values from our dict and assign to vars
                cloudsecurity_auth_url, cloudsecurity_client_id, cloudsecurity_client_secret = itemgetter(
                    "cloudsecurity_auth_url", "cloudsecurity_client_id", "cloudsecurity_client_secret"
                )(config)

                # Validate the inputs and get the current cloudsecurity DC back
                self._validate_config(
                    client_id=cloudsecurity_client_id,
                    client_secret=cloudsecurity_client_secret,
                    auth_url=cloudsecurity_auth_url,
                )

        except FileNotFoundError:
            pass

            try:
                print("i m here")
                cloudsecurity_client_id = str(os.getenv("cloudsecurity_client_id"))
                cloudsecurity_client_secret = str(os.getenv("cloudsecurity_client_secret"))
                cloudsecurity_auth_url = str(os.getenv("cloudsecurity_auth_url"))

                # Validate the inputs and get the current cloudsecurity DC back
                self._validate_config(
                    client_id=cloudsecurity_client_id,
                    client_secret=cloudsecurity_client_secret,
                    auth_url=cloudsecurity_auth_url,
                )

            except Exception:
                sys.exit(
                    f"[ERROR] Unable to find one or more cloudsecurity environment variables. Please check them and try again."
                )

        return (
            cloudsecurity_auth_url,
            cloudsecurity_client_id,
            cloudsecurity_client_secret,
        )

    # @_generic_exception_handler
    def _request_cloudsecurity_api_token(
        self, auth_url: str, client_id: str, client_secret: str
    ) -> str:
        """
        Request a token to be used to authenticate against the cloudsecurity API

        Parameters:
            - client_id: the cloudsecurity client ID
            - client_secret: the cloudsecurity secret

        Returns:
            - TOKEN: A session token
        """
        audience = (
            "cloudsecurity-api"
            if "auth.app" in auth_url or "auth.gv" in auth_url
            else "beyond-api"
        )

        auth_payload = {
            "grant_type": "client_credentials",
            "audience": audience,
            "client_id": client_id,
            "client_secret": client_secret,
        }

        # Initliaze a timer
        func_time = Timer("+ Requesting cloudsecurity API token")

        with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
            # Request token from the cloudsecurity API
            response = requests.post(
                url=auth_url, headers=self.HEADERS_AUTH, data=auth_payload, timeout=None
            )

            if response.status_code != requests.codes.ok:
                raise Exception(
                    f"Error authenticating to cloudsecurity {response.status_code} - {response.text}"
                )

            try:
                response_json = response.json()
                TOKEN = response_json.get("access_token")
                if not TOKEN:
                    message = "Could not retrieve token from cloudsecurity: {}".format(
                        response_json.get("message")
                    )
                    raise Exception(message)
            except ValueError as exception:
                print(exception)
                raise Exception("Could not parse API response")
            self.HEADERS["Authorization"] = "Bearer " + TOKEN

            response_json_decoded = json.loads(
                base64.standard_b64decode(self._pad_base64(TOKEN.split(".")[1]))
            )

            self.cloudsecurity_dc = response_json_decoded["dc"]


############### End Classes ###############


############### Start Queries and Vars ###############
cloud_config_rules_query = """
query CloudConfigurationSettingsTable(
    $first: Int
    $after: String
    $filterBy: CloudConfigurationRuleFilters
    $orderBy: CloudConfigurationRuleOrder
    $projectId: [String!]
  ) {
    cloudConfigurationRules(
      first: $first
      after: $after
      filterBy: $filterBy
      orderBy: $orderBy
    ) {
      analyticsUpdatedAt
      nodes {
        id
        shortId
        name
        description
        enabled
        severity
        serviceType
        cloudProvider
        subjectEntityType
        functionAsControl
        builtin
        targetNativeTypes
        remediationInstructions
        hasAutoRemediation
        supportsNRT
        createdAt
        updatedAt
        control {
          id
        }
        analytics(selection: { projectId: $projectId }) {
          passCount
          failCount
        }
        scopeAccounts {
          id
        }
      }
      pageInfo {
        endCursor
        hasNextPage
      }
      totalCount
    }
  }
"""

cloud_config_rules_query_vars = {
    "first": 500,
    "orderBy": {"field": "FAILED_CHECK_COUNT", "direction": "DESC"},
}

############### End Queries and Vars ###############


############### Start Functions ###############
def _generic_exception_handler(function: Any) -> Any:
    """
    Private decorator function for error handling

    Parameters:
        - function: the function to pass in

    Returns:
        - _inner_function: the decorated function
    """

    def _inner_function(*args: Any, **kwargs: Any) -> Any:
        try:
            function_result = function(*args, **kwargs)
            return function_result
        except ValueError as v_err:
            print(traceback.format_exc(), f"{v_err}")
            sys.exit(1)
        except Exception as err:
            if (
                "502: Bad Gateway" not in str(err)
                and "503: Service Unavailable" not in str(err)
                and "504: Gateway Timeout" not in str(err)
            ):
                print(traceback.format_exc(), f"[ERROR]: {err}")
                return err

            else:
                print(traceback.format_exc(), "[ERROR] - Retry")

            sys.exit(1)

    return _inner_function


def print_logo(client: cloudsecurityClient) -> None:
    """
    Print out the cloudsecurity logo and script information

    Parameters:
        - none

    Returns:
        - none
    """

    print(
        f"""
 
+----------------------------------------------------------------------+
  cloudsecurity DATACENTER: {BLUE}{client.cloudsecurity_dc}{END}
  API URL: {BLUE}{client.api_url}{END}
  AUTH URL: {BLUE}{client.auth_url}{END} 
+----------------------------------------------------------------------+
  SCRIPT NAME: {BLUE}{SCRIPT_NAME}{END}
+----------------------------------------------------------------------+
  {SCRIPT_DESCRIPTION}
+----------------------------------------------------------------------+
  OUTPUT CSV: {BLUE}{CSV_FNAME}-<timestamp>.csv{END}
+----------------------------------------------------------------------+"""
    )


@_generic_exception_handler
def query_cloudsecurity_api(client: cloudsecurityClient, query: str, variables: dict) -> dict:
    """
    Query the cloudsecurity API for the given query data schema
    Parameters:
        - query: the query or mutation we want to run
        - variables: the variables to be passed with the query or mutation
    Returns:
        - result: a json representation of the request object
    """

    # Init counters for retries, backoff
    retries = 0
    backoff = 1

    response = requests.post(
        url=client.api_url,
        json={"variables": variables, "query": query},
        headers=client.HEADERS,
    )

    code = response.status_code

    # Handle retries, and exponential backoff logic
    while code != requests.codes.ok:
        # Increment backoff counter
        # Retries look like 1, 2, 4, 16, 32
        backoff = backoff * 2
        if retries >= MAX_QUERY_RETRIES:
            raise Exception(
                f"[ERROR] Exceeded the maximum number of retries [{response.status_code}] - {response.text}"
            )

        if code == requests.codes.unauthorized or code == requests.codes.forbidden:
            raise Exception(
                f"[ERROR] Authenticating to cloudsecurity [{response.status_code}] - {response.text}"
            )
        if code == requests.codes.not_found:
            raise Exception(f"[ERROR] Unknown error [{response.status_code}]")

        if backoff != 0:
            print(f"\n└─ Backoff triggered, waiting {backoff}s and retrying.")

        time.sleep(backoff)

        response = requests.post(
            url=client.api_url,
            json={"variables": variables, "query": query},
            headers=client.HEADERS,
        )
        code = response.status_code
        retries += 1

    # Catch edge case where we get a valid response but empty response body
    if not response:
        time.sleep(backoff)
        response = requests.post(
            url=client.api_url,
            json={"variables": variables, "query": query},
            headers=client.HEADERS,
        )
        raise Exception(f"\n API returned no data or emtpy data set. Retrying.")

    response_json = response.json()

    if response_json.get("errors"):
        errors = response_json.get("errors")[0]
        raise Exception(
            f'\n └─ MESSAGE: {errors["message"]}, \n └─ CODE: {errors["extensions"]["code"]}'
        )

    if response_json.get("code") == "DOWNSTREAM_SERVICE_ERROR":
        errors = response_json.get("errors")
        request_id = errors["message"].partition("request id: ")[2]

        raise Exception(
            f"[ERROR] - DOWNSTREAM_SERVICE_ERROR - request id: {request_id}"
        )

    return response_json


@_generic_exception_handler
def get_api_result(client: cloudsecurityClient) -> pd.DataFrame:
    """
    A wrapper around the query_cloudsecurity_api function
    That fetches the cloud controls for the tenant

    Parameters:
        - none

    Returns:
        - df: a pandas dataframe
    """

    # Initliaze a timer
    func_time = Timer("+ Fetching Issues from cloudsecurity")

    with yaspin(text=func_time, color="white"):
        # Query the cloudsecurity API
        result = query_cloudsecurity_api(
            client=client,
            query=cloud_config_rules_query,
            variables=cloud_config_rules_query_vars,
        )

        # Get the unique query key for the query
        query_key = str(list(result["data"].keys())[0])

        df = pd.json_normalize(
            result["data"][query_key]["nodes"], sep="_", errors="ignore"
        )

        page_info = result["data"][query_key]["pageInfo"]

        # Count starting at 1 because we always sent at least 1 page
        page_count = 1

        # Continue querying until we have no pages left
        while page_info["hasNextPage"]:
            # Increment page count with each page
            page_count += 1

            # Advance the cursor
            cloud_config_rules_query_vars["after"] = page_info["endCursor"]

            # Query the API, now with a new after value
            result = query_cloudsecurity_api(
                client=client,
                query=cloud_config_rules_query,
                variables=cloud_config_rules_query_vars,
            )

            df = pd.concat(
                [
                    df,
                    pd.json_normalize(
                        result["data"][query_key]["nodes"], sep="_", errors="ignore"
                    ),
                ]
            )

            page_info = result["data"][query_key]["pageInfo"]

    print(
        func_time,
        f'\n└─ DONE: Got {GREEN}{page_count}{END} pages containing {GREEN}{result["data"][query_key]["totalCount"]}{END} results',
    )

    return df


############### End Functions ###############


def main() -> None:
    # Build a cloudsecurity client
    cloudsecurity_client = cloudsecurityClient(cloudsecurity_config_file=cloudsecurity_CONFIG_PATH)
    # Print the cloudsecurity logo and script info
    print_logo(client=cloudsecurity_client)

    # Fetch the issues from the API, returned as a pandas df
    df = get_api_result(client=cloudsecurity_client)

    # Get timezone information in UTC
    timestamp_now = f"{datetime.now(timezone.utc)}Z".replace(" ", "T").replace(
        "+00:00", ""
    )

    timestamped_fname = f"{CSV_FNAME}-{timestamp_now}.csv"

    func_time = Timer(f"+ Writing results to file")

    with yaspin(text=func_time, color=random.choice(SPINNER_COLORS)):
        # any columns you want to exclude from the CSV
        # df.loc[:, df.columns != ""]
        df.to_csv(timestamped_fname, encoding="utf-8")

    print(
        func_time,
        f"\n└─ DONE: Wrote data to file:\n└── {GREEN}{timestamped_fname}{END}",
    )

    end_time = datetime.now()

    total_elapsed_time = (
        f"{round((end_time - start_time).total_seconds(),1)}"
        if (end_time - start_time).total_seconds() < 60
        # round rounds down by default, so we include a remainder in the calculation to force
        # a round up in the minutes calculation withouth having to include an additional library
        else f"{round(((end_time - start_time).total_seconds() // 60 + ((end_time - start_time).total_seconds()% 60 > 0)))}:{round(((end_time - start_time).total_seconds()% 60),1)}"
    )

    print(f"+ Script Finished\n└─ Total script elapsed time: {total_elapsed_time}s")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n+ Ctrl+C interrupt received. Exiting.")
        pass
