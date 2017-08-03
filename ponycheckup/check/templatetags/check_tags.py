# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django import template
from django.conf import settings


register = template.Library()


@register.assignment_tag
def get_settings_var(var_name):
    """
    Returns value of a variable ``var_name`` from settings module

    Usage::

        {% load check_tags %}
        {% get_settings_var [var_name] as [value_var] %}

    ``var_name`` is a variable name
    ``value_var`` is a variable value

    Example usage::

        {% load check_tags %}
        {% get_settings_var "LOGIN_URLS" as urls %}
        Login urls: {{ urls }}

    """
    try:
        return getattr(settings, var_name)
    except Exception:
        return None
