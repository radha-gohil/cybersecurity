function TimelinePanel({
    timeline = {},
}) {
    const events =
        timeline.events || [];


    const formatDate = (
        value
    ) => {
        if (!value) {
            return "Time unavailable";
        }

        const date =
            new Date(value);

        if (
            Number.isNaN(
                date.getTime()
            )
        ) {
            return value;
        }

        return date.toLocaleString();
    };


    const readableEventType = (
        value
    ) => {
        if (!value) {
            return "Event";
        }

        return String(value)
            .replaceAll("_", " ");
    };


    return (
        <section className="detail-panel full-width-panel">

            <div className="panel-heading">

                <div>

                    <h3>
                        Attack Timeline
                    </h3>

                    <p>
                        Chronological reconstruction
                        of correlated incident activity.
                    </p>

                </div>


                <div className="timeline-count">

                    {events.length}
                    {" "}
                    events

                </div>

            </div>


            {events.length === 0 ? (

                <div className="empty-inline">
                    No attack timeline is available.
                </div>

            ) : (

                <div className="timeline-list">

                    {events.map(
                        (
                            item,
                            index
                        ) => (

                        <div
                            className="timeline-item"
                            key={
                                item.timeline_id
                                || index
                            }
                        >

                            <div
                                className={
                                    `timeline-marker ${
                                        eventClass(
                                            item.event_type
                                        )
                                    }`
                                }
                            />


                            <div className="timeline-content">

                                <div className="timeline-top">

                                    <div>

                                        <strong>
                                            {
                                                readableEventType(
                                                    item.event_type
                                                )
                                            }
                                        </strong>

                                        <span className="timeline-sequence">
                                            Event #
                                            {
                                                item.sequence_no
                                                ?? index + 1
                                            }
                                        </span>

                                    </div>


                                    <span>
                                        {
                                            formatDate(
                                                item.event_time
                                            )
                                        }
                                    </span>

                                </div>


                                <p>
                                    {
                                        item.description
                                        || "No description available."
                                    }
                                </p>


                                {
                                    item.event
                                    && Object.keys(
                                        item.event
                                    ).length > 0
                                    && (

                                    <details className="timeline-details">

                                        <summary>
                                            View event metadata
                                        </summary>

                                        <pre>
                                            {
                                                JSON.stringify(
                                                    item.event,
                                                    null,
                                                    2
                                                )
                                            }
                                        </pre>

                                    </details>
                                )}

                            </div>

                        </div>
                    ))}

                </div>
            )}

        </section>
    );
}


function eventClass(
    eventType
) {
    const value =
        String(
            eventType || ""
        ).toUpperCase();

    if (
        value.includes(
            "PROCESS"
        )
    ) {
        return "process";
    }

    if (
        value.includes(
            "FILE"
        )
    ) {
        return "file";
    }

    if (
        value.includes(
            "NETWORK"
        )
    ) {
        return "network";
    }

    if (
        value.includes(
            "PERSISTENCE"
        )
        || value.includes(
            "REGISTRY"
        )
    ) {
        return "persistence";
    }

    return "other";
}


export default TimelinePanel;