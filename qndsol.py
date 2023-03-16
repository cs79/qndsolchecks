import sys
import os
import re

# helper functions to perform regex-based checks, and print findings with line number info

# a function to perform a regex match on a provided string using a provided regex, returning the character position of the start of the match
def regex_match(string, regex):
    # assume regex has already been compiled
    # find first match
    match = regex.search(string)
    if match is None:
        # return -1 if no match
        print("No match for regex: {}".format(regex.pattern))
        return -1
    # return start position of match
    return match.start()

# a function taking a list of strings and a character position, and returning the line number of the string containing the character position
def get_line_number(lines, pos):
    # if pos is -1, return -1
    if pos == -1:
        print("No matching line number found")
        return -1
    # iterate over lines in lines list
    for i in range(len(lines)):
        # check if pos is within the length of the line
        if pos < len(lines[i]):
            # return line number
            return i+1
        # subtract length of line from pos
        pos -= len(lines[i])
    # return -1 if pos is not within the length of the lines list
    print("No matching line number found")
    return -1

# a function to check a provided string for a regex match using regex_match, returning the line number and position of the match using get_line_number
def check_regex_match(string, lines, regex):
    # perform regex match
    pos = regex_match(string, regex)
    # return line number of match
    return get_line_number(lines, pos)

# a function to check for text patterns that look like function names containing the word "random"
def check_random_function(string, lines):
    print("\nChecking for possible random functions\n")
    # regex pattern to match (possible) function names that look like they might be randomness functions
    pattern = re.compile(r"\s+\w*rand\w*\(")
    line_number = check_regex_match(string, lines, pattern)
    if line_number != -1:
        print("Line {} contains a possible random function definition or call - be wary of relying on on-chain pseudorandomness for any critical functionality".format(line_number))

# a function to check for text patterns that look like loops containing transfers
def check_transfer_loop(string, lines):
    print("\nChecking for possible loops containing transfers\n")
    # regex pattern to match (possible) loops that contain transfers
    for_pattern = re.compile(r"for\s*\([\w\s]+\;\s*[\w\s\<\>\=\.\(\)]+\;\s*[\w\s\+\-\(\)]+\)\s*\{[\w\s\\\(\)\[\]\.]+(transfer\(|send\()")
    line_number = check_regex_match(string, lines, for_pattern)
    if line_number != -1:
        print("For loop construct on line {} appears to contain a transfer - disbursement of funds could be stalled by an attacker".format(line_number))
    do_pattern = re.compile(r"do\s*\{[\w\s\\\(\)\[\]\.]+(transfer\(|send\()")
    line_number = check_regex_match(string, lines, do_pattern)
    if line_number != -1:
        print("Do loop construct on line {} appears to contain a transfer - disbursement of funds could be stalled by an attacker".format(line_number))
    while_pattern = re.compile(r"while\s*\([\w\s\<\>\=\.\(\)]+\)\s*\{[\w\s\\\(\)\[\]\.]+(transfer\(|send\()")
    line_number = check_regex_match(string, lines, while_pattern)
    if line_number != -1:
        print("While loop construct on line {} appears to contain a transfer - disbursement of funds could be stalled by an attacker".format(line_number))

# main function
def main():
    # get filename variable from command line argument
    filename = sys.argv[1]
    # check that passed filename exists in os.path
    if not os.path.exists(filename):
        print("File not found")
        sys.exit(1)
    # open file
    f = open(filename, 'r')
    # also read lines from f into a list
    lines = f.readlines()
    # close file
    f.close()
    # also combine lines into a single string
    file_contents = ''.join(lines)
    
    # run the various checks
    check_random_function(file_contents, lines)
    check_transfer_loop(file_contents, lines)

    print('\n')

if __name__ == '__main__':
    main()
