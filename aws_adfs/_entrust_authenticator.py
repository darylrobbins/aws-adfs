import click
import lxml.etree as ET

import logging
import re

try:
    # Python 3
    from urllib.parse import urlparse, parse_qs
except ImportError:
    # Python 2
    from urlparse import urlparse, parse_qs

from . import roles_assertion_extractor

def extract(html_response, ssl_verification_enabled, session):
    """
    :param response: raw http response
    :param html_response: html result of parsing http response
    :return:
    """

    roles_page_url = _action_url_on_validation_success(html_response)

    # Ensure that we're dealing with a token authenticator
    if html_response.find('.//div[@id="authResponseControls"]') is None:
        raise click.ClickException(
            u'Unsupported authentication type; Only challenge/response is supported'
        )
    elif html_response.find('.//div[@id="pvnControls"][@style="display:normal"]') is not None: 
        raise click.ClickException(
            u'Authentication requiring PVN is not supported'
        )

    question_label_element = html_response.find('.//label[@for="authResponse"]')
    if question_label_element is not None:
        click.echo(''.join(question_label_element.xpath('text()|*/text()')))

    entrust_token = click.prompt(text='Enter your Entrust challenge response', type=str)

    click.echo('Going for aws roles', err=True)

    return _retrieve_roles_page(
        roles_page_url,
        _context(html_response),
        session,
        ssl_verification_enabled,
        entrust_token,
    )

def _context(html_response):
    context_query = './/input[@id="context"]'
    element = html_response.find(context_query)
    return element.get('value')


def _retrieve_roles_page(roles_page_url, context, session, ssl_verification_enabled,
                         entrust_token):
    response = session.post(
        roles_page_url,
        verify=ssl_verification_enabled,
        allow_redirects=True,
        data={
            'AuthMethod': 'EntrustIdentityGuardADFSPlugin',
            'Context': context,
            'ChallengeParamName1': entrust_token,
        }
    )
    logging.debug(u'''Request:
            * url: {}
            * headers: {}
        Response:
            * status: {}
            * headers: {}
            * body: {}
        '''.format(roles_page_url, response.request.headers, response.status_code, response.headers,
                   response.text))

    if response.status_code != 200:
        raise click.ClickException(
            u'Issues during redirection to aws roles page. The error response {}'.format(
                response
            )
        )

    # Save session cookies to avoid having to repeat MFA on each login
    session.cookies.save(ignore_discard=True)

    html_response = ET.fromstring(response.text, ET.HTMLParser())
    return roles_assertion_extractor.extract(html_response)

def _action_url_on_validation_success(html_response):
    vip_auth_method = './/form[@id="options"]'
    element = html_response.find(vip_auth_method)
    return element.get('action')
