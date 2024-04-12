import argparse
import os
import queue
import requests
import signal
import sys
import threading
import time
import uuid

from gpsdclient import GPSDClient
from loguru import logger
from itertools import chain
from scapy.all import *

"""
        # Get the USB info
        (manuf, product, serial) = self.get_rtl_usb_info(intnum)

        # Hash the slot, manuf, product, and serial, to get a unique ID for the UUID
        devicehash = kismetexternal.Datasource.adler32("{}{}{}{}".format(intnum, manuf, product, serial))
        devicehex = "0000{:02X}".format(devicehash)
"""

class GPSTracker:
    AGEOFF_THRESHOLD = 30 # default: 30 seconds

    def __init__(self):
        self._stopped_event = threading.Event()
        self._location = {"timestamp": int(time.time()), "mode": 1, "lat": 0.0, "lon": 0.0, "alt": 0.0, "spd": 0.0}
        self._thread = None
    
    def should_keep_running(self):
        """Determines whether the thread should continue running."""
        return not self._stopped_event.is_set()
    
    def start(self):
        self._thread = threading.Thread(target=self.run)
        logger.info("Starting GPS tracker.")
        self._thread.start()
    
    def stop(self):
        logger.info("Stopping GPS tracker.")
        self._stopped_event.set()
        if self._thread is threading.Thread:
            return self._thread.join()

    def run(self):
        logger.debug("Connecting to GPSd.")
        with GPSDClient() as self.gpsdclient:
            for result in self.gpsdclient.dict_stream(filter=["TPV"]):
                if not self.should_keep_running():
                    break

                if result["mode"] in (2, 3):
                    self._location = { "timestamp": int(result["time"].timestamp()), 
                                      "lat": result["lat"], 
                                      "lon": result["lon"] }

                    if result["mode"] == 3:
                        # alt 	Optional, GPS altitude in meters
                        self._location["alt"] = result["alt"]
                    else:
                        self._location["alt"] = 0.0
                    
                    if result["speed"] >= 0:
                        # spd 	Optional, GPS speed in kilometers per hour
                        self._location["spd"] = result["speed"]*(3600/1000)
                    else:
                        self._location["spd"] = 0.0
                else:
                    # mode 1 = no fix
                    self._location = {"timestamp": int(time.time()), "mode": 1, "lat": 0.0, "lon": 0.0, "alt": 0.0, "spd": 0.0}

                # logger.debug(self._location)
        logger.debug("Disconnected from GPSd.")

    def get_latest(self):
        timestamp = int(time.time())

        # if gps location is older than threshold, it has aged off
        location_age = timestamp - self._location["timestamp"]
        if location_age < self.AGEOFF_THRESHOLD:
            return self._location
        else:
            # @todo reduce how often this warning is returned?
            logger.warning(f"GPS location aged off ({location_age}s), check GPS puck or GPSD source")

        return {"timestamp": int(time.time()), "mode": 1, "lat": 0.0, "lon": 0.0, "alt": 0.0, "spd": 0.0}


class BluetoothScanner:
    def __init__(self, interface, _queue, gps):
        self.interface = interface
        self.queue = _queue
        self.gps = gps
        self._thread = None
        self._stopped_event = threading.Event()
    
    def should_keep_running(self):
        """Determines whether the thread should continue running."""
        return not self._stopped_event.is_set()
    
    def start(self):
        self._thread = threading.Thread(target=self.run)
        logger.info("Starting BLE scanner.")
        self._thread.start()
    
    def stop(self):
        logger.info("Stopping BLE scanner.")
        self._stopped_event.set()
        if self._thread is threading.Thread:
            return self._thread.join()
    
    def run(self):
        def stop_callback(_):
            if self.should_keep_running():
                return False
            else:
                return True 
            
        def packet_callback(packet):
            reports = chain.from_iterable(p[HCI_LE_Meta_Advertising_Reports].reports for p in packet)
            location = self.gps.get_latest()
            
            for report in reports:
                data = {
                    "btaddr": report[HCI_LE_Meta_Advertising_Report].addr, # required
                    "timestamp": int(time.time()), # remove decimals
                    "signal": report[HCI_LE_Meta_Advertising_Report].rssi,
                    "lat": location["lat"],
                    "lon": location["lon"],
                    "alt": location["alt"],
                    "spd": location["spd"]
                }

                logger.debug(data)
                
                try:
                    # if queue is full, raises Full
                    # prevents hung threads at exit
                    self.queue.put_nowait(data)
                    logger.debug(f"Queue size: {self.queue.qsize()}")
                except self.queue.Full:
                    logger.warning("BLE packet writer queue full, dropping packet.")
        
        hci_index = int(self.interface[3:])
        with BluetoothHCISocket(hci_index) as bt:
            # Enable scan mode
            ans, unans = bt.sr(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Set_Scan_Enable(enable=True, filter_dups=False), verbose=0)
            if len(unans):
                logger.warning(f"Scan enable command for `hci{hci_index}` went unanswered.")
            if len(ans):
                for _, r in ans:
                    if r[HCI_Event_Command_Complete].status:
                        logger.warning(f"Failed to enable scan mode for `hci{hci_index}`, this may affect results, but can be ignored.")
            
            logger.debug(f"Enabled scan mode. (hci{hci_index})")

            # Start sniffing
            bt.sniff(lfilter=lambda p: HCI_LE_Meta_Advertising_Reports in p,
                     prn=packet_callback,
                     store=0,
                     stop_filter=stop_callback)

        logger.debug(f"Stopped BLE scanner.")


# class WiFiScanner:
#     pass


class ScanReporter:
    REPORT_INTERVAL = 5 # default: 5 seconds

    def __init__(self, endpoint, apikey, source_name, source_uuid, _queue):
        self._stopped_event = threading.Event()
        self._thread = None
        self.endpoint = endpoint
        self.apikey = apikey
        self.source_name = source_name
        self.source_uuid = source_uuid
        self.queue = _queue
    
    def should_keep_running(self):
        """Determines whether the thread should continue running."""
        return not self._stopped_event.is_set()
    
    def start(self):
        self._thread = threading.Thread(target=self.run)
        logger.info("Starting scan reporter.")
        self._thread.start()
    
    def stop(self):
        logger.info(f"Stopping scan reporter, this may take up to {self.REPORT_INTERVAL} seconds.")
        self._stopped_event.set()
        if self._thread is threading.Thread:
            return self._thread.join()

    def run(self):
        logger.info("Scan reporter started.")

        # @todo deal with kismet not running (connection refused, etc.)

        with requests.Session() as s:
            s.cookies.set('KISMET', self.apikey)

            payload = {"source_uuid": self.source_uuid, 
                       "source_name": self.source_name, 
                       "reports": []}
            
            event = threading.Event()
            while self.should_keep_running():
                logger.debug(f"Waiting {self.REPORT_INTERVAL} seconds.")
                event.wait(self.REPORT_INTERVAL) # blocking here ensures queue is emptied on exit
                if not self.queue.empty():
                    for i in range(self.queue.qsize()):
                        item = self.queue.get()
                        payload["reports"].append(item)
                    logger.info(f"Reports in payload: {len(payload['reports'])}")
                    with s.post(self.endpoint, json=payload) as resp:
                        logger.debug(resp)
                    payload["reports"].clear()
                else:
                    logger.info("Queue empty.")
        
        logger.info("Stopped scan reporter.")

class ScanReportd:
    # s = ScanReportd(host_uri=args.host_uri, apikey=args.apikey, use_ssl=args.use_ssl, name=args.name, uuid=args.uuid)
    def __init__(self, host_uri, apikey, use_ssl=False, source_name=None, source_uuid=None):
        self.exit_event = threading.Event()  # Event used for clean exit
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)

        self.queue = queue.Queue()
        self.gps = GPSTracker()

        endpoint = f"{'https' if use_ssl else 'http'}://{host_uri}/phy/phybluetooth/scan/scan_report.cmd"
        self.reporter = ScanReporter(endpoint, apikey, source_name, source_uuid, self.queue)
    
    def handle_signal(self, signum, frame):
        logger.warning(f"Received {signal.Signals(signum).name}")
        self.exit()
    
    def exit(self):
        self.exit_event.set()
        self.gps.stop()
        self.scanner.stop()
        self.reporter.stop()

    def start_bluetooth(self, interface):
        self.scanner = BluetoothScanner(interface, self.queue, self.gps)
        self.gps.start()
        self.scanner.start()
        self.reporter.start()
    
    # def start_wifi(self, interface):
    #     pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Simple hack to show "optional" arguments as required
    required_args = parser.add_argument_group('required arguments')
    required_args.add_argument("--connect", dest="host_uri", required=True, help="address of kismet server (host:port)")
    required_args.add_argument("--apikey", dest="apikey", required=True, help="requires admin or scanreport role")
    required_args.add_argument("--uuid", dest="uuid", help="datasource uuid (if blank, script will reuse self-generated)")
    required_args.add_argument("--name", dest="name", help="name to show in web ui (if blank, script will reuse self-generated)")
    datasource_group = parser.add_argument_group('datasource')
    datasource_args = datasource_group.add_mutually_exclusive_group(required=True)
    datasource_args.add_argument("--bluetooth", dest="bluetooth", metavar="HCI", help="bluetooth interface (e.g. hci0)")
    # datasource_args.add_argument("--wifi", dest="wifi", metavar="WLAN", help="wifi interface (e.g. wlan0)")
    # optional
    parser.add_argument("--ssl", dest="use_ssl", action='store_true', help="use secure connection")
    parser.add_argument("--debug", dest="debug", action='store_true', help="enable debug output")
    
    args = parser.parse_args()

    # Let's make sure we're running as root
    # We do this after the initial argparse to allow --help calls as non-root
    if not (os.geteuid() == 0):
        logger.error("This script must run as root; please use sudo.")
    else:
        if not args.debug:
            logger.remove()
            logger.add(sys.stderr, level="INFO")
        
        s = ScanReportd(host_uri=args.host_uri, apikey=args.apikey, use_ssl=args.use_ssl, source_name=args.name, source_uuid=args.uuid)

        if args.bluetooth:
            s.start_bluetooth(args.bluetooth)
        # elif args.wifi:
        #     s.start_wifi(args.wifi)
        else:
            logger.error("No datasource specified, exiting.")
