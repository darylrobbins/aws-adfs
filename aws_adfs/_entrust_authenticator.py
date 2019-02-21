import click
import lxml.etree as ET

import logging
from time import time, sleep
import re

try:
    # Python 3
    from urllib.parse import urlparse, parse_qs, urlencode
except ImportError:
    # Python 2
    from urlparse import urlparse, parse_qs
    from urllib import urlencode

from . import roles_assertion_extractor

challenge_info = '\nA Soft Token challenge has been sent to the Entrust ST app with reference # {}'
challenge_wait = 'Waiting for challenge response '
time_out = 150
timed_out = "Timed out"


def display_challenge(ref_num):
    click.echo(challenge_info.format(ref_num), nl=True)
    click.echo(challenge_wait, nl=False)


def check_error(html_response):
    for error_field in ['errorText', 'errorMsg']:
        error_element = html_response.find('.//label[@id="{}"]'.format(error_field))
        if error_element is not None:
            raise click.ClickException(error_element.text)


def waiter(url, context, polling_interval, timeout, session, prev=None):
    limit = time() + timeout
    while time() < limit:
        click.echo('.', nl=False)

        session.headers.update({'X-Requested-With': 'XMLHttpRequest',
                                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0',
                                'Referer': url,
                                'Host': 'adfstest.entrustdatacard.com',
                                'Accept': '*/*',
                                'Accept-Language': 'en-US,en;q=0.5',
                                'Accept-Encoding': 'gzip, deflate, br',
                                'Content-Type': 'text/plain;charset=UTF-8'
                                })
        response = session.post(url,
                                data=urlencode([
                                    ('AuthMethod', 'EntrustIdentityGuardADFSPlugin'),
                                    ('Context', context),
                                    ('postURL', url),
                                    ('responseData', ''),
                                    ('chlAnswered', 'FALSE')
                                ]))

        if response.status_code != 200:
            raise click.ClickException(
                u'Issues during wait for challenge response. The error response {}'.format(response)
            )

        html_response = ET.fromstring(response.text, ET.HTMLParser())
        check_error(html_response)

        answered = _chl_answered(html_response)
        if answered is True:
            click.echo('', nl=True)
            return
        elif answered is None:
            check_error(html_response)
        else:
            ref_num = _chl_ref_num(html_response)
            if ref_num != prev:
                display_challenge(ref_num)
                prev = ref_num
            sleep(polling_interval)
    raise click.ClickException(timed_out)


def extract(html_response, ssl_verification_enabled, session):
    """
    :param html_response: html result of parsing http response
    :param ssl_verification_enabled:
    :param session:
    :return:
    """

    check_error(html_response)

    roles_page_url = _action_url_on_validation_success(html_response)

    # Ensure that we're dealing with a token authenticator
    auth_method = html_response.find('.//input[@id="authMethod"]')
    if auth_method is not None and auth_method.get('value') == "EntrustIdentityGuardADFSPlugin":

        challenge_ref_num = html_response.find('.//label[@for="challengeRefNum"]')
        if challenge_ref_num is not None:
            prev = challenge_ref_num.findtext('b')
            display_challenge(prev)

        waiter(_url(html_response), _context(html_response),
               _polling_interval(html_response), time_out, session, prev)

    elif html_response.find('.//input[@id="authResponseControls"]') is None:
        raise click.ClickException(
            u'Unsupported authentication type; Only challenge/response is supported'
        )
    elif html_response.find('.//div[@id="pvnControls"][@style="display:normal"]') is not None:
        raise click.ClickException(
            u'Authentication requiring PVN is not supported'
        )

    else:
        question_label_element = html_response.find('.//label[@for="authResponse"]')
        if question_label_element is not None:
            click.echo(''.join(question_label_element.xpath('text()|*/text()')))

        entrust_token = click.prompt(text='Enter your Entrust challenge response', type=str)  # TODO: !!

    return _retrieve_roles_page(
        roles_page_url,
        _context(html_response),
        session,
        ssl_verification_enabled,
        # entrust_token,  # TODO: !!
    )


def _chl_ref_num(html_response):
    crn = html_response.find('.//label[@for="challengeRefNum"]')
    if crn is not None:
        return crn.findtext('b')


def _chl_answered(html_response):
    answered = html_response.find('.//input[@id="chlAnswered"]')
    if answered is not None:
        return answered.get('value') == "TRUE"
    return None


def _polling_interval(html_response):
    return int(html_response.find('.//input[@id="pollingInterval"]').get('value'))


def _url(html_response):
    raw_url = html_response.find('.//form[@id="options"]').get('action').split("?")[0]
    return re.sub(r':\d+', '', raw_url)


def _context(html_response):
    context_query = './/input[@id="context"]'
    element = html_response.find(context_query)
    return element.get('value')


def _retrieve_roles_page(roles_page_url, context, session, ssl_verification_enabled):
                         # ,entrust_token):
    response = session.post(
        roles_page_url,
        verify=ssl_verification_enabled,
        allow_redirects=True,
        data={
            'AuthMethod': 'EntrustIdentityGuardADFSPlugin',
            'Context': context,
            # 'ChallengeParamName1': entrust_token,
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
