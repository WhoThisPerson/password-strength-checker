# Password Strength Checker

A Python command-line utility that evaluates password strength using an entropy-based scoring system and checks for known password breaches using the Have I Been Pwned API.

The application estimates password strength based on password length and character diversity, then checks whether the password has appeared in known data breaches. It uses SHA-1 hashing and the API's k-anonymity model to minimize the information shared with the external service.

## Features

- **Entropy-Based Strength Estimation:** Estimates password entropy using password length and the size of the character set represented in the password.
- **Strength Scoring:** Assigns a strength score from 0 to 4 based on configurable entropy thresholds.
- **Breach Detection:** Checks passwords against the [Have I Been Pwned Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords).
- **Privacy-Conscious API Integration:** Hashes passwords locally using SHA-1 and sends only the first five characters of the hash to the API. The remaining hash characters are compared locally.
- **Error Handling:** Handles API timeouts, connection failures, unsuccessful HTTP responses, and other request-related errors.
- **Hidden Password Input:** Uses Python's `getpass` module to prevent passwords from being displayed in the terminal during input.
- **Interactive CLI:** Allows users to check multiple passwords in a single session.

## Technologies

- **Language:** Python
- **Libraries:** `requests`, `hashlib`, `math`, `string`, `getpass`
- **External API:** Have I Been Pwned Pwned Passwords API

## How It Works

### 1. Password Entropy Estimation

The application estimates password entropy using password length and character diversity.

It identifies whether the password contains lowercase letters, uppercase letters, digits, whitespace, and punctuation. The sizes of the corresponding character sets are combined to estimate the number of possible characters.

The entropy estimate is calculated as:

`Entropy = Password Length × log₂(Character Set Size)`

For example, a password containing lowercase letters, uppercase letters, and digits uses an estimated character set of 62 characters.

The resulting entropy estimate is compared against configurable thresholds to assign a strength score.

| Score | Classification | Entropy Threshold |
|---|---|---|
| 0 | Very Weak | Below 28 bits |
| 1 | Weak | 28 to less than 36 bits |
| 2 | OK | 36 to less than 60 bits |
| 3 | Good | 60 to less than 80 bits |
| 4 | Strong | 80 bits or higher |

These thresholds are configurable and are intended as a simplified strength-estimation model rather than a definitive security assessment.

### 2. Password Breach Detection

The application checks whether a password appears in known breach datasets using the Have I Been Pwned Pwned Passwords API.

The process follows these steps:

1. **Hash the password:** Calculate the password's SHA-1 hash locally.
2. **Split the hash:** Separate the first five hexadecimal characters from the remaining characters.
3. **Query the API:** Send only the five-character prefix to the Pwned Passwords range endpoint.
4. **Compare locally:** Examine the returned hash suffixes and compare them against the remaining characters of the password's hash.
5. **Report the result:** Return the number of known occurrences, or zero if no matching hash is found.

This approach implements the API's k-anonymity model: the complete password and its full hash are not sent to the API.

**Note:** SHA-1 is used here for compatibility with the breach-checking API, not for securely storing passwords.

### 3. Error Handling

The application distinguishes between a successful breach check and a failed API request.

It handles common request failures, including:

- Request timeouts.
- Connection failures.
- Unsuccessful HTTP responses.
- Other request-related exceptions.

If the API check fails, the application reports that the breach count is unavailable instead of incorrectly treating the password as having zero known breaches. The entropy-based strength score can still be calculated independently.

## Getting Started

### Prerequisites

- Python 3.10 or later.
- An internet connection for password breach checks.

### Installation

1. Clone the repository:

   ```bash
   git clone git@github.com:[YOUR USERNAME]/password-strength-checker.git
   ```

### Running the Application

Run the script using Python:

```bash
python3 password_checker.py
```

Enter a password when prompted. After the result is displayed, enter `Y` to check another password or `N` to exit.

## Example Usage

```text
Continue? (Y/N): Y
Enter password:
Password Strength: 4
Breach Count: 0

Continue? (Y/N): N
```

*Example output is illustrative. Actual strength scores and breach counts depend on the password entered and the API response.*

The strength score ranges from `0` (weakest) to `4` (strongest). A breach count of `0` means the password was not found in the API's returned results; it does not guarantee that the password has never been compromised.

## Limitations

- **Simplified entropy estimation:** The calculation assumes characters are selected randomly from the estimated character set. Human-created passwords often follow predictable patterns, so the estimate may overstate their actual strength.
- **No dictionary or pattern analysis:** The current implementation does not detect common passwords, predictable sequences, or other patterns that can make passwords easier to guess.
- **External API dependency:** Breach detection requires network access and availability of the Have I Been Pwned service.
