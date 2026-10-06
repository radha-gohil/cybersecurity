from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from endpoint.collectors.system_abuse_monitor import (
    SystemAbuseMonitor,
)

from endpoint.utils.logger import (
    get_logger,
)


logger = get_logger(__name__)


try:

    import win32evtlog

    PYWIN32_AVAILABLE = True


except ImportError:

    win32evtlog = None

    PYWIN32_AVAILABLE = False


class WindowsSystemCollector:
    """
    Read-only Windows Security Event Log collector for system-abuse evidence.

    Event IDs:
        4672 - special privileges assigned
        4720 - user account created
        4728 - member added to global security group
        4732 - member added to local security group
        4698 - scheduled task created
        1102 - Security log cleared
        4719 - system audit policy changed
    """

    SECURITY_LOG_NAME = "Security"

    SYSTEM_EVENT_IDS = (
        4672,
        4720,
        4728,
        4732,
        4698,
        1102,
        4719,
    )


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
        system_detection_mode: str = "SHADOW",
        system_monitor=None,
    ):

        self.poll_interval = float(
            poll_interval
        )

        self.max_events_per_poll = int(
            max_events_per_poll
        )


        if self.poll_interval <= 0:

            raise ValueError(
                "poll_interval must be positive"
            )


        if self.max_events_per_poll <= 0:

            raise ValueError(
                "max_events_per_poll must be positive"
            )


        self.system_monitor = (
            system_monitor
            if system_monitor is not None
            else SystemAbuseMonitor(
                system_detection_mode=
                    system_detection_mode
            )
        )


        self.running = False

        self.processed_record_ids = set()


        logger.info(
            "WindowsSystemCollector initialized | "
            "Polling=%.1fs | MaxEvents=%s | DetectionMode=%s",
            self.poll_interval,
            self.max_events_per_poll,
            getattr(
                self.system_monitor,
                "system_detection_mode",
                "UNKNOWN",
            ),
        )


    def is_backend_available(
        self,
    ) -> bool:

        return PYWIN32_AVAILABLE


    @staticmethod
    def normalize_text(
        value,
    ) -> str:

        return str(
            value
            if value is not None
            else ""
        ).strip()


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


            if name:

                fields[
                    name
                ] = (
                    item.text
                    or ""
                )


        return fields


    def parse_event_xml(
        self,
        xml_text: str,
    ) -> Optional[Dict]:

        try:

            root = ET.fromstring(
                xml_text
            )


        except (
            ET.ParseError,
            TypeError,
            ValueError,
        ):

            logger.exception(
                "Unable to parse Windows system security event XML"
            )

            return None


        system = root.find(
            "e:System",
            self.XML_NAMESPACE,
        )


        if system is None:

            return None


        event_node = system.find(
            "e:EventID",
            self.XML_NAMESPACE,
        )


        if (
            event_node is None
            or not event_node.text
        ):

            return None


        try:

            event_id = int(
                event_node.text
            )


        except ValueError:

            return None


        if event_id not in self.SYSTEM_EVENT_IDS:

            return None


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


        fields = (
            self.get_event_data_fields(
                root
            )
        )


        username = (
            self.normalize_text(
                fields.get(
                    "SubjectUserName"
                )
            )
        )


        target_username = (
            self.normalize_text(
                fields.get(
                    "TargetUserName"
                )
            )
        )


        group_name = (
            self.normalize_text(
                fields.get(
                    "TargetUserName"
                )
            )
            if event_id in {
                4728,
                4732,
            }
            else ""
        )


        member_name = (
            self.normalize_text(
                fields.get(
                    "MemberName"
                )
            )
        )


        privilege_list = (
            self.normalize_text(
                fields.get(
                    "PrivilegeList"
                )
            )
        )


        task_name = (
            self.normalize_text(
                fields.get(
                    "TaskName"
                )
            )
        )


        task_content = (
            self.normalize_text(
                fields.get(
                    "TaskContent"
                )
            )
        )


        subcategory = (
            self.normalize_text(
                fields.get(
                    "SubcategoryGuid"
                )
                or fields.get(
                    "SubcategoryId"
                )
            )
        )


        change = " ".join(
            value
            for value
            in [
                self.normalize_text(
                    fields.get(
                        "AuditPolicyChanges"
                    )
                ),
                self.normalize_text(
                    fields.get(
                        "CategoryId"
                    )
                ),
            ]
            if value
        )


        return {
            "event_type":
                "windows_system_security_event",

            "windows_event_id":
                event_id,

            "record_id":
                record_id,

            "timestamp":
                timestamp,

            "username":
                username,

            "target_username":
                target_username,

            "group_name":
                group_name,

            "member_name":
                member_name,

            "privilege_list":
                privilege_list,

            "task_name":
                task_name,

            "task_command":
                task_content,

            "task_content":
                task_content,

            "subcategory":
                subcategory,

            "change":
                change,

            "source":
                "windows_security_log",

            "synthetic_test":
                False,
        }


    # ============================================================
    # READ SECURITY LOG
    # ============================================================

    def query_recent_events(
        self,
    ) -> List[str]:

        if not PYWIN32_AVAILABLE:

            raise RuntimeError(
                "pywin32 is not installed. "
                "Windows Event Log access is unavailable."
            )


        id_clause = " or ".join(
            f"EventID={event_id}"
            for event_id
            in self.SYSTEM_EVENT_IDS
        )


        query = (
            "*[System["
            f"({id_clause})"
            "]]"
        )


        flags = (
            win32evtlog.EvtQueryChannelPath
            |
            win32evtlog.EvtQueryReverseDirection
        )


        query_handle = None

        rendered = []


        try:

            query_handle = (
                win32evtlog.EvtQuery(
                    self.SECURITY_LOG_NAME,
                    flags,
                    query,
                )
            )


            handles = (
                win32evtlog.EvtNext(
                    query_handle,
                    self.max_events_per_poll,
                )
            )


            for handle in handles:

                try:

                    rendered.append(
                        win32evtlog.EvtRender(
                            handle,
                            win32evtlog.EvtRenderEventXml,
                        )
                    )


                finally:

                    try:

                        win32evtlog.EvtClose(
                            handle
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


        return rendered


    # ============================================================
    # NORMALIZED EVENT HANDLING
    # ============================================================

    def process_normalized_event(
        self,
        system_event: Dict,
    ):

        record_id = (
            system_event.get(
                "record_id"
            )
        )


        if (
            record_id is not None
            and record_id
            in self.processed_record_ids
        ):

            return None


        event_id = (
            system_event.get(
                "windows_event_id"
            )
        )


        try:

            event_id = int(
                event_id
            )

        except (
            TypeError,
            ValueError,
        ):

            return None


        if event_id not in self.SYSTEM_EVENT_IDS:

            return None


        if record_id is not None:

            self.processed_record_ids.add(
                record_id
            )


        return (
            self.system_monitor.process_system_event(
                system_event
            )
        )


    # ============================================================
    # POLL
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

            xml_events = (
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
                "Unable to read Windows Security log for "
                "system-abuse events | %s",
                error,
            )

            return summary


        summary[
            "events_read"
        ] = len(
            xml_events
        )


        for xml_text in xml_events:

            parsed = (
                self.parse_event_xml(
                    xml_text
                )
            )


            if parsed is None:

                continue


            summary[
                "events_parsed"
            ] += 1


            result = (
                self.process_normalized_event(
                    parsed
                )
            )


            if result is not None:

                summary[
                    "events_processed"
                ] += 1


        return summary


    # ============================================================
    # LIFECYCLE
    # ============================================================

    def start(
        self,
    ):

        logger.info(
            "Starting SENTINEL-X Windows System Collector..."
        )

        logger.info(
            "Collector mode: READ-ONLY Windows Security Event Log"
        )

        logger.info(
            "System-abuse detection mode: %s",
            getattr(
                self.system_monitor,
                "system_detection_mode",
                "UNKNOWN",
            ),
        )


        self.running = True


        try:

            while self.running:

                summary = (
                    self.poll_once()
                )


                logger.info(
                    "SYSTEM SECURITY POLL | "
                    "Read=%s | Parsed=%s | Processed=%s | Errors=%s",
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
                "Windows System Collector interrupted."
            )


        finally:

            self.stop()


    def stop(
        self,
    ):

        self.running = False

        logger.info(
            "SENTINEL-X Windows System Collector stopped."
        )
