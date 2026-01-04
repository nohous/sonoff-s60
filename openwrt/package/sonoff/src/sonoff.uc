#!/usr/bin/ucode
/*
 * sonoff.uc - Sonoff S60TPF smart plug controller for OpenWRT
 *
 * Usage: ucode sonoff.uc <on|off|energy>
 *
 * Requires: aes_cbc.so module in /usr/lib/ucode/
 */

import * as fs from 'fs';
import * as aes from 'aes_cbc';

/* Device configuration - edit these! */
//const DEVICE_IP = '192.168.104.230';
//const DEVICE_ID = '10026edf5c';
//const API_KEY = '7f3aba54-ee51-40df-bca6-69358ed17f13';
//const DEVICE_KEY = '8584fe79-2214-495e-9494-7af70921b803';

const DEVICE_IP = '192.168.1.28';
const DEVICE_ID = '10026ede0c';
const DEVICE_KEY = '3cc3bdc8-20fd-44be-b348-44b8bba4bdbb';
const API_KEY = '265da2d7-bb39-42c4-9047-9960178f706b';

/* Timestamp in milliseconds */
function timestamp_ms() {
    /* ucode doesn't have ms precision, fake it */
    let t = time();
    return sprintf('%d000', t);
}

/* Send HTTP POST and return JSON response */
function http_post(url, payload) {
    let json_data = sprintf('%J', payload);

    /* Use curl with proper headers */
    let cmd = sprintf(
        "curl -s --max-time 5 " +
        "-H 'Content-Type: application/json' " +
        "-H 'Connection: close' " +
        "-d '%s' '%s'",
        replace(json_data, "'", "'\\''"),
        url
    );

    let proc = fs.popen(cmd, 'r');
    if (!proc) {
        return null;
    }

    let response = proc.read('all');
    proc.close();

    if (!response || response == '') {
        return null;
    }

    return json(response);
}

/* Encrypt data for device */
function encrypt(data, devicekey) {
    let json_str = sprintf('%J', data);
    return aes.encrypt(json_str, devicekey);
}

/* Decrypt response from device */
function decrypt(msg, devicekey) {
    let plaintext = aes.decrypt(msg.iv, msg.data, devicekey);
    if (!plaintext) {
        return null;
    }
    return json(plaintext);
}

/* Send on/off command */
function send_command(ip, deviceid, devicekey, apikey, params) {
    let url = sprintf('http://%s:8081/zeroconf/switches', ip);

    let encrypted = encrypt(params, devicekey);

    let payload = {
        sequence: timestamp_ms(),
        deviceid: deviceid,
        selfApikey: '123',
        encrypt: true,
        iv: encrypted.iv,
        data: encrypted.data
    };

    let result = http_post(url, payload);

    if (!result) {
        die('Failed to connect to device\n');
    }

    if (result.error != 0) {
        die(sprintf('Command failed: error %d\n', result.error));
    }

    return result;
}

/* Get energy consumption data */
function get_energy(ip, deviceid, devicekey, apikey, start, end) {
    let url = sprintf('http://%s:8081/zeroconf/getHoursKwh', ip);

    let encrypted = encrypt({ getHoursKwh: { start: start, end: end } }, devicekey);

    let payload = {
        sequence: timestamp_ms(),
        deviceid: deviceid,
        selfApikey: apikey,
        encrypt: true,
        iv: encrypted.iv,
        data: encrypted.data
    };

    let result = http_post(url, payload);

    if (!result) {
        die('Failed to connect to device\n');
    }

    if (result.error != 0) {
        die(sprintf('Energy query failed: error %d\n', result.error));
    }

    /* Decrypt response */
    if (result.encrypt) {
        return decrypt(result, devicekey);
    }

    return result;
}

/* Decode energy hex string */
function decode_energy(hex_data) {
    let hours = [];
    for (let i = 0; i < length(hex_data); i += 3) {
        let hex_digit = substr(hex_data, i, 1);
        let dec_part = substr(hex_data, i + 1, 2);

        /* Convert hex digit to int */
        let h = index('0123456789abcdef', lc(hex_digit));
        if (h < 0) h = 0;

        let d = int(dec_part) || 0;
        let kwh = h + d * 0.01;
        push(hours, kwh);
    }
    return hours;
}

/* Main */
function main() {
    if (length(ARGV) < 1) {
        printf('Usage: ucode sonoff.uc <command>\n');
        printf('Commands: on, off, energy\n');
        exit(1);
    }

    let command = ARGV[0];

    if (command == 'energy') {
        printf('Querying energy data (last 24 hours)...\n');

        let energy = get_energy(DEVICE_IP, DEVICE_ID, DEVICE_KEY, API_KEY, 0, 23);
        printf('%J\n', energy);

        if (energy && energy.hoursKwhData) {
            let hours = decode_energy(energy.hoursKwhData);

            printf('\nEnergy per hour (last %d hours):\n', length(hours));
            let total = 0;
            for (let i = 0; i < length(hours); i++) {
                printf('  Hour %d: %.2f kWh\n', i, hours[i]);
                total += hours[i];
            }
            printf('\nTotal: %.2f kWh\n', total);
        }
    }
    else if (command == 'on' || command == 'off') {
        let params = {
            switches: [{ outlet: 0, switch: command }],
            operSide: 1
        };

        send_command(DEVICE_IP, DEVICE_ID, DEVICE_KEY, API_KEY, params);
        printf('SUCCESS\n');
    }
    else {
        printf('Unknown command: %s\n', command);
        printf('Commands: on, off, energy\n');
        exit(1);
    }
}

main();
