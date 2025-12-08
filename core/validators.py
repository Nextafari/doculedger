import phonenumbers
from phonenumbers.phonenumberutil import NumberParseException

from django.core.exceptions import ValidationError


def validate_phonenumber(value):
    value = value if isinstance(value, str) else f"+{value}"

    # Validate a user's phone number.
    try:
        phonenumbers.parse(value, None)
    except NumberParseException:
        err_msg = f"Mobile number {value} is invalid. Be sure to include + and country code alongside a valid mobile number."
        raise ValidationError(err_msg)
