import os
import re
from datetime import datetime
from urllib.parse import unquote

#Results directory creation
def create_results_folder():
    results_folder = "Results"
    if not os.path.exists(results_folder):
        os.makedirs(results_folder)

# Dictionary creation: the original pattern as key and the compiled pattern as value
def build_wordlist_dict(wordlist_file_path):
    # Uploading wordlist
    wordlist_dict = {}
    with open(wordlist_file_path, 'r', encoding="utf8") as wordlist_file:
        for line in wordlist_file:
            pattern = line.strip() #Remove white spaces 
            wordlist_dict[pattern] = re.compile(re.escape(pattern), re.IGNORECASE) # Create regex object
    return wordlist_dict

def search_for_xss_attacks(log_file_path, wordlist_dict):
    # Open log file and search matching with the XSS patterns
    with open(log_file_path, 'r', encoding="utf8") as log_file:
        log_lines = log_file.readlines()

    xss_attacks = []
    for line_number, line in enumerate(log_lines, start=1):
        # Decode rows using unquote() to handle URL encoding
        decoded_line = unquote(line)
        
        for pattern, regex in wordlist_dict.items():
            if regex.search(decoded_line):
                xss_attacks.append((line_number, decoded_line.strip()))

    return xss_attacks

if __name__ == "__main__":
    wordlist_file_path = "xss-payload-list.txt"

    log_file_path = input("Enter the full path of the log file you want to analyze: ")

    if not os.path.exists(log_file_path):
        print(f"Log file '{log_file_path}' doesn't exist.")
    elif not os.path.exists(wordlist_file_path):
        print("Wordlist not found. Ensure to insert correct path.")
    else:

        create_results_folder() #Create directory "results" if not exists
        wordlist_dict = build_wordlist_dict(wordlist_file_path)
        xss_attacks = search_for_xss_attacks(log_file_path, wordlist_dict)

        results_folder = "Results"
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        output_file_path = os.path.join(results_folder, f"xss_results_{timestamp}.log")
        with open(output_file_path, "w", encoding="utf-8") as output_file:

            if len(xss_attacks) > 0:
                print(f"Found {len(xss_attacks)} potential XSS attacks:\n")
                for line_number, line_content in xss_attacks:
                    output_file.write(f"{line_content}\n")
                print(f"Results saved to '{output_file_path}")
            else:
                output_file.write("No XSS attack found.")
                print("No XSS attack found.")
