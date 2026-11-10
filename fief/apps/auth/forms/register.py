from typing import TypeVar

from fastapi import Depends
from wtforms import EmailField, FormField, HiddenField, validators

from fief.dependencies.register import get_optional_registration_session
from fief.dependencies.user_field import get_registration_user_fields
from fief.forms import BaseForm, CSRFBaseForm, PasswordCreateFieldForm, get_form_field
from fief.locale import gettext_lazy as _
from fief.models import RegistrationSession, UserField


class RegisterFormBase(CSRFBaseForm):
    email = EmailField(
        _("Email address"), validators=[validators.InputRequired(), validators.Email()]
    )
    fields: FormField


RF = TypeVar("RF", bound=RegisterFormBase)


async def get_register_form_class(
    registration_user_fields: list[UserField] = Depends(get_registration_user_fields),
    registration_session: RegistrationSession | None = Depends(
        get_optional_registration_session
    ),
) -> type[RF]:
    class RegisterFormFields(BaseForm):
        pass

    for field in registration_user_fields:
        setattr(RegisterFormFields, field.slug, get_form_field(field))

    class RegisterForm(RegisterFormBase):
        fields = FormField(RegisterFormFields, separator=".")

    # The password is chosen when confirming the email, see RegisterConfirmForm
    return RegisterForm


class RegisterConfirmForm(CSRFBaseForm, PasswordCreateFieldForm):
    token = HiddenField(validators=[validators.InputRequired()])
