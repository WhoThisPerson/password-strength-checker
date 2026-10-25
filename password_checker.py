import string
import getpass
import math
import requests
import hashlib

# Password entropy calculation variables
MIN_LENGTH = 8
LOWERCASE_LENGTH = 26
UPPERCASE_LENGTH = 26
NUM_DIGITS = 10
NUM_SPACE = 1
UNIQUE_CHAR_LENGTH = len(string.punctuation)

# Entropy cuttoff variables
VERY_WEAK_ENTROPY = 28
WEAK_ENTROPY = 36
OK_ENTROPY = 60
GOOD_ENTROPY = 80

# Scoring variables
VERY_WEAK = 0
WEAK = 1
OK = 2
GOOD = 3
STRONG = 4

# Have I Been Pwned URLs
HASH_RANGE_URL = "https://api.pwnedpasswords.com/range"

def calculate_entropy(password, password_length) -> int:
    """
    - Calculates entropy based on character diversity and length
    - Finds appearances of character type and adds to a running character set size
    - Higher the character set size, the better
    """

    has_lower = False
    has_upper = False
    has_digit = False
    has_space = False
    has_punct = False

    for char in password:
        if char in string.ascii_lowercase:
            has_lower = True
        elif char in string.ascii_uppercase:
            has_upper = True
        elif char in string.digits:
            has_digit = True
        elif char in string.punctuation:
            has_punct = True
        elif char.isspace():
            has_space = True

    charset_size = (
        (LOWERCASE_LENGTH if has_lower else 0)
        + (UPPERCASE_LENGTH if has_upper else 0)
        + (NUM_DIGITS if has_digit else 0)
        + (UNIQUE_CHAR_LENGTH if has_punct else 0)
        + (NUM_SPACE if has_space else 0)
    )

    return password_length * math.log2(charset_size) if charset_size else 0

def check_password_strength():
    """
    - Calculates password strength and grades it on a scale of 0-4
    - with 0 being the weakest and 4 being the strongest
    """

    password = getpass.getpass("Enter password: ")
    password_length = len(password)

    if password_length < MIN_LENGTH:
        print(f"Password is too short; Suggesting that it be longer than {password_length} characters")
        return

    entropy = calculate_entropy(password, password_length)
    breach_count = check_pwned(password)

    if entropy < VERY_WEAK_ENTROPY:
        score = VERY_WEAK

    elif entropy < WEAK_ENTROPY:
        score = WEAK

    elif entropy < OK_ENTROPY:
        score = OK

    elif entropy < GOOD_ENTROPY:
        score = GOOD

    else:
        score = STRONG

    print(f"Password Strength: {score}")

    if breach_count is None:
        print("Breach Count: Unable to determine")
    else:
        print(f"Breach Count: {breach_count}")

def check_pwned(password) -> int | None:
    """
    - Cross checks entered password with Have I Been Pwned 
      for any prior breaches and prints out count of breaches
    - Encodes input password with SHA1 for Have I Been Pwned
      for partial hash via k-anonymity model using first 5 characters
      of SHA-1 hash
    
      Returns:
        int: Number of times password appeared in known breaches
        0: Password was not found in the database
        None: The API check failed
    """

    # Encodes password in sha1 and splits into first five and rest
    encoded_password = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = encoded_password[:5]
    suffix = encoded_password[5:]

    # Make request to the API
    url = f"{HASH_RANGE_URL}/{prefix}"

    try:
        response = requests.get(
            url,
            headers={
                "Add-Padding": "true",
                "User-Agent": "PasswordStrengthChecker"
            },
            timeout=10
        )

        response.raise_for_status()

    except requests.exceptions.Timeout:
        print("Error: Breach check timed out")
        return None

    except requests.exceptions.ConnectionError:
        print("Error: Unable to connect to breach-checking service")
        return None

    except requests.exceptions.HTTPError as error:
        print(f"Error: Service returned an HTTP Error")
        print(f"Status Code: {error.response.status_code}")
        return None

    except requests.exceptions.RequestException as error:
        print(f"Error: Breach Check Failed: {error}")
        return None

    # Go through returned list of hashes and compare seen suffixes
    # with the current encoded password's suffix for breaches
    for line in response.text.splitlines():
        hash_suffix, _, count = line.partition(":")

        if hash_suffix == suffix:
            return int(count)

    # Password wasn't found in prior breaches
    return 0

def main():
    """
    - Entry point
    - Continues to ask user for password input until stopped
    """

    while True:
        choice = input("Continue? (Y/N): ").strip().upper()

        if choice == "Y":
            return True
        elif choice == "N":
            return False
        else:
            print("Invalid choice. Enter either Y/N")

if __name__ == "__main__":
    check_password_strength()
    while main():
        check_password_strength()
