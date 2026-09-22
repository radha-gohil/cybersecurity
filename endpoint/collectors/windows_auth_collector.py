import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from endpoint.collectors.auth_monitor import (
    AuthMonitor,
)

from endpoint.utils.logger import (
    get_logger,
)


logger = get_logger(__name__)


# ================================================================
# OPTIONAL WINDOWS EVENT LOG DEPENDENCY
# ================================================================

try:

    import win32evtlog

    PYWIN32_AVAILABLE = True

except ImportError:

    win32evtlog = None

    PYWIN32_AVAILABLE = False


class WindowsAuthCollector:
    """
    SENTINEL-X Windows Authentication Collector.

    READ-ONLY COMPONENT.

    The collector reads Windows Security Event Log entries and
    converts authentication events into SENTINEL-X auth metadata.

    Supported Windows Event IDs:

        4624 -> successful logon
        4625 -> failed logon

    The collector does NOT:

        - perform login attempts
        - modify accounts
        - change passwords
        - enable auditing
        - change Windows security policy
        - clear event logs
    """

    SECURITY_LOG_NAME = (
        "Security"
    )

    SUCCESS_LOGON_EVENT_ID = (
        4624
    )

    FAILED_LOGON_EVENT_ID = (
        4625
    )

    # ============================================================
    # WINDOWS EVENT XML NAMESPACE
    # ============================================================

    XML_NAMESPACE = {
        "e":
            (
                "http://schemas.microsoft.com/"
                "win/2004/08/events/event"
            )
    }

    def __init__(
        self,
        poll_interval: float = 5.0,
        max_events_per_poll: int = 50,
    ):

        self.poll_interval = (
            poll_interval
        )

        self.max_events_per_poll = (
            max_events_per_poll
        )

        self.auth_monitor = (
            AuthMonitor()
        )

        self.running = False

        # --------------------------------------------------------
        # Prevent processing the same Windows event repeatedly
        # during one collector runtime.
        # --------------------------------------------------------

        self.processed_record_ids = set()

    # ============================================================
    # DEPENDENCY STATUS
    # ============================================================

    def is_backend_available(
        self,
    ) -> bool:

        return (
            PYWIN32_AVAILABLE
        )

    # ============================================================
    # SAFE TEXT
    # ============================================================

    def normalize_text(
        self,
        value,
    ) -> str:

        if value is None:

            return ""

        return str(
            value
        ).strip()

    # ============================================================
    # XML HELPER
    # ============================================================

    def get_event_data_fields(
        self,
        root,
    ) -> Dict[str, str]:

        fields = {}

        event_data = root.find(
            "e:EventData",
            self.XML_NAMESPACE,
        )

        if event_data is None:

            return fields

        for item in event_data.findall(
            "e:Data",
            self.XML_NAMESPACE,
        ):

            name = (
                item.attrib.get(
                    "Name"
                )
            )

            if not name:

                continue

            fields[
                name
            ] = (
                item.text
                or ""
            )

        return fields

    # ============================================================
    # PARSE WINDOWS EVENT XML
    # ============================================================

    def parse_event_xml(
        self,
        xml_text: str,
    ) -> Optional[Dict]:

        try:

            root = (
                ET.fromstring(
                    xml_text
                )
            )

        except (
            ET.ParseError,
            TypeError,
            ValueError,
        ) as error:

            logger.warning(
                "Unable to parse Windows event XML | %s",
                error,
            )

            return None

        # ========================================================
        # SYSTEM SECTION
        # ========================================================

        system = root.find(
            "e:System",
            self.XML_NAMESPACE,
        )

        if system is None:

            return None

        event_id_node = system.find(
            "e:EventID",
            self.XML_NAMESPACE,
        )

        if event_id_node is None:

            return None

        try:

            event_id = int(
                event_id_node.text
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

        if event_id not in {

            self.SUCCESS_LOGON_EVENT_ID,

            self.FAILED_LOGON_EVENT_ID,
        }:

            return None

        # ========================================================
        # EVENT RECORD ID
        # ========================================================

        record_id = None

        record_node = system.find(
            "e:EventRecordID",
            self.XML_NAMESPACE,
        )

        if (
            record_node is not None
            and record_node.text
        ):

            try:

                record_id = int(
                    record_node.text
                )

            except ValueError:

                record_id = None

        # ========================================================
        # SYSTEM TIME
        # ========================================================

        timestamp = None

        time_node = system.find(
            "e:TimeCreated",
            self.XML_NAMESPACE,
        )

        if time_node is not None:

            timestamp = (
                time_node.attrib.get(
                    "SystemTime"
                )
            )

        # ========================================================
        # EVENT DATA
        # ========================================================

        fields = (
            self.get_event_data_fields(
                root
            )
        )

        username = (
            self.normalize_text(
                fields.get(
                    "TargetUserName"
                )
            )
        )

        domain = (
            self.normalize_text(
                fields.get(
                    "TargetDomainName"
                )
            )
        )

        source_ip = (
            self.normalize_text(
                fields.get(
                    "IpAddress"
                )
            )
        )

        source_port = (
            self.normalize_text(
                fields.get(
                    "IpPort"
                )
            )
        )

        workstation = (
            self.normalize_text(
                fields.get(
                    "WorkstationName"
                )
            )
        )

        logon_type = (
            self.normalize_text(
                fields.get(
                    "LogonType"
                )
            )
        )

        process_name = (
            self.normalize_text(
                fields.get(
                    "ProcessName"
                )
            )
        )

        status_code = (
            self.normalize_text(
                fields.get(
                    "Status"
                )
            )
        )

        sub_status = (
            self.normalize_text(
                fields.get(
                    "SubStatus"
                )
            )
        )

        # --------------------------------------------------------
        # Windows often represents local/unknown IP values as "-".
        # --------------------------------------------------------

        if source_ip in {
            "",
            "-",
            "::1",
        }:

            source_ip = (
                "local"
            )

        # ========================================================
        # NORMALIZE TO SENTINEL-X AUTH FORMAT
        # ========================================================

        if (
            event_id
            ==
            self.FAILED_LOGON_EVENT_ID
        ):

            normalized_event_type = (
                "login_failure"
            )

            result = (
                "failed"
            )

        else:

            normalized_event_type = (
                "login_success"
            )

            result = (
                "success"
            )

        return {

            "event_type":
                normalized_event_type,

            "windows_event_id":
                event_id,

            "record_id":
                record_id,

            "timestamp":
                timestamp,

            "username":
                username,

            "domain":
                domain,

            "source_ip":
                source_ip,

            "source_port":
                source_port,

            "workstation":
                workstation,

            "logon_type":
                logon_type,

            "process_name":
                process_name,

            "result":
                result,

            "status_code":
                status_code,

            "sub_status":
                sub_status,

            "source":
                "windows_security_log",

            "synthetic_test":
                False,
        }

    # ============================================================
    # QUERY WINDOWS SECURITY EVENT LOG
    # ============================================================

    def query_recent_events(
        self,
    ) -> List[str]:

        if not PYWIN32_AVAILABLE:

            raise RuntimeError(
                "pywin32 is not installed. "
                "Windows Event Log access is unavailable."
            )

        # --------------------------------------------------------
        # Only request authentication events.
        # --------------------------------------------------------

        query = (
            "*[System["
            "(EventID=4624 or EventID=4625)"
            "]]"
        )

        flags = (

            win32evtlog.EvtQueryChannelPath

            |

            win32evtlog.EvtQueryReverseDirection
        )

        query_handle = None

        event_handles = []

        rendered_events = []

        try:

            query_handle = (
                win32evtlog.EvtQuery(
                    self.SECURITY_LOG_NAME,
                    flags,
                    query,
                )
            )

            event_handles = (
                win32evtlog.EvtNext(
                    query_handle,
                    self.max_events_per_poll,
                )
            )

            for event_handle in event_handles:

                try:

                    xml_text = (
                        win32evtlog.EvtRender(
                            event_handle,
                            win32evtlog.EvtRenderEventXml,
                        )
                    )

                    rendered_events.append(
                        xml_text
                    )

                except Exception as error:

                    logger.warning(
                        "Unable to render Windows event | %s",
                        error,
                    )

                finally:

                    try:

                        win32evtlog.EvtClose(
                            event_handle
                        )

                    except Exception:

                        pass

        finally:

            if query_handle is not None:

                try:

                    win32evtlog.EvtClose(
                        query_handle
                    )

                except Exception:

                    pass

        return rendered_events

    # ============================================================
    # PROCESS ONE NORMALIZED EVENT
    # ============================================================

    def process_normalized_event(
        self,
        auth_event: Dict,
    ):

        record_id = (
            auth_event.get(
                "record_id"
            )
        )

        # --------------------------------------------------------
        # Deduplicate Windows EventRecordID.
        # --------------------------------------------------------

        if (
            record_id is not None
            and record_id
            in self.processed_record_ids
        ):

            return None

        if record_id is not None:

            self.processed_record_ids.add(
                record_id
            )

        # --------------------------------------------------------
        # Skip unusable account records.
        # --------------------------------------------------------

        username = (
            self.normalize_text(
                auth_event.get(
                    "username"
                )
            )
        )

        if username in {
            "",
            "-",
        }:

            return None

        # --------------------------------------------------------
        # Feed into existing AuthMonitor.
        # --------------------------------------------------------

        return (
            self.auth_monitor.process_auth_event(
                auth_event
            )
        )

    # ============================================================
    # POLL ONCE
    # ============================================================

    def poll_once(
        self,
    ) -> Dict:

        summary = {

            "backend_available":
                PYWIN32_AVAILABLE,

            "events_read":
                0,

            "events_parsed":
                0,

            "events_processed":
                0,

            "errors":
                [],
        }

        if not PYWIN32_AVAILABLE:

            summary[
                "errors"
            ].append(
                "pywin32 is not installed."
            )

            return summary

        try:

            event_xml_list = (
                self.query_recent_events()
            )

        except Exception as error:

            summary[
                "errors"
            ].append(
                str(
                    error
                )
            )

            logger.warning(
                "Unable to read Windows Security log | %s",
                error,
            )

            return summary

        summary[
            "events_read"
        ] = len(
            event_xml_list
        )

        for xml_text in event_xml_list:

            auth_event = (
                self.parse_event_xml(
                    xml_text
                )
            )

            if auth_event is None:

                continue

            summary[
                "events_parsed"
            ] += 1

            result = (
                self.process_normalized_event(
                    auth_event
                )
            )

            if result is not None:

                summary[
                    "events_processed"
                ] += 1

        return summary

    # ============================================================
    # START
    # ============================================================

    def start(
        self,
    ):

        logger.info(
            "Starting SENTINEL-X Windows Auth Collector..."
        )

        logger.info(
            "Collector mode: READ-ONLY Windows Security Event Log"
        )

        self.running = True

        try:

            while self.running:

                summary = (
                    self.poll_once()
                )

                logger.info(
                    "AUTH COLLECTOR POLL | "
                    "Read=%s | "
                    "Parsed=%s | "
                    "Processed=%s | "
                    "Errors=%s",

                    summary.get(
                        "events_read"
                    ),

                    summary.get(
                        "events_parsed"
                    ),

                    summary.get(
                        "events_processed"
                    ),

                    len(
                        summary.get(
                            "errors",
                            [],
                        )
                    ),
                )

                time.sleep(
                    self.poll_interval
                )

        except KeyboardInterrupt:

            logger.info(
                "Windows Auth Collector interrupted."
            )

        finally:

            self.stop()

    # ============================================================
    # STOP
    # ============================================================

    def stop(
        self,
    ):

        self.running = False

        logger.info(
            "SENTINEL-X Windows Auth Collector stopped."
        )


# ================================================================
# MANUAL READ-ONLY RUN
# ================================================================

if __name__ == "__main__":

    collector = (
        WindowsAuthCollector(
            poll_interval=5.0,
            max_events_per_poll=25,
        )
    )

    collector.start()