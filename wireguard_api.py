#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wireguard API
health and metrics exports.
"""
import wireguard as wg
from flask import Flask
from flask import Response
from prometheus_client import generate_latest


__author__ = "Guillaume Delpierre"
__credits__ = ["Guillaume Delpierre"]
__license__ = "GNU GPLv3"
__version__ = "0.1.0"
__maintainer__ = "Guillaume Delpierre"
__email__ = "github@llew.me"
__status__ = "Dev"

app = Flask(__name__)


def interfaces_status():
    """
    Get all wireguard up interfaces and return status.
    """
    # get running interfaces
    interface_dump, stderr = wg.Wireguard().dump_running_conf()
    wg_dump = wg.dump_to_dict(interface_dump, sanitize=True)

    interfaces = wg_dump.keys()
    status = {}

    if bool(interfaces):
        for key in interfaces:
            key = key.decode('utf-8')
            status.update(
                {
                    key:
                    {
                        'http_status': 200,
                        'status': 'OK'
                    }
                }
            )

    return status


@app.route('/')
def index():
    """meow."""
    return Response('meow!', status=200)


@app.route('/health', methods=['GET'])
def health():
    """
    Wireguard global interface health status.
    Returns status code 503 if no interface.
    """
    mimetype = 'application/json'
    status = interfaces_status()
    resp = wg.to_json(status)

    if not status:
        return Response(resp, status='503', mimetype=mimetype)

    return Response(resp, status='200', mimetype=mimetype)


@app.route('/health/<interface>', methods=['GET'])
def interface_health(interface):
    """
    Wireguard named interface health status.
    Returns 200 if interface is up, 404 if interface is not found.
    """
    mimetype = 'application/json'
    resp = interfaces_status()

    try:
        return Response(wg.to_json(resp[interface]),
                        status='200',
                        mimetype=mimetype)

    except KeyError:
        return Response('{}', status='404', mimetype=mimetype)


@app.route('/metrics', methods=['GET'])
def prometheus_metrics_exporters():
    """
    Export prometheus metrics.
    """
    interface_dump, stderr = wg.Wireguard().dump_running_conf()
    wg_dump = wg.dump_to_dict(interface_dump, sanitize=True)

    metrics = wg.METRICS
    wg_dump = wg.convert(wg_dump)

    content_type = str('text/plain; version=0.0.4; charset=utf-8')

    for interface in wg_dump.keys():
        if not wg.is_link_up(interface):
            status = 503
        else:
            status = 200
        metrics['interface_stats'].labels(
            interface=interface, status=status).inc()

        for elmt in ['transfer_tx', 'transfer_rx', 'latest_handshake']:
            for peer in wg_dump[interface]['peers']:
                metrics[elmt].labels(
                    interface=interface,
                    peer_name=peer,
                    peer_master=wg_dump[interface]['public_key'],
                ).set(wg_dump[interface]['peers'][peer][elmt])

    return Response(generate_latest(), mimetype=content_type)
