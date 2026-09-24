import {
    useState,
} from "react";

import {
    approveSOCCase,
    rejectSOCCase,
} from "../../services/socApi";

import "./AnalystDecisionPanel.css";


function AnalystDecisionPanel({
    incidentId,
    caseStatus,
    approvalStatus,
    onDecisionComplete,
}) {

    const [
        analyst,
        setAnalyst,
    ] = useState("SOC Analyst");


    const [
        comment,
        setComment,
    ] = useState("");


    const [
        loading,
        setLoading,
    ] = useState(false);


    const [
        message,
        setMessage,
    ] = useState("");


    const [
        error,
        setError,
    ] = useState("");


    const normalizedApproval =
        String(
            approvalStatus || ""
        ).toUpperCase();


    const normalizedCaseStatus =
        String(
            caseStatus || ""
        ).toUpperCase();


    const alreadyApproved =
        normalizedApproval === "APPROVED"
        || normalizedCaseStatus === "APPROVED";


    const alreadyRejected =
        normalizedApproval === "REJECTED"
        || normalizedCaseStatus === "REJECTED";


    const decisionCompleted =
        alreadyApproved
        || alreadyRejected;


    // ============================================================
    // APPROVE
    // ============================================================

    const handleApprove = async () => {

        if (
            !analyst.trim()
        ) {

            setError(
                "Analyst name is required."
            );

            return;
        }


        try {

            setLoading(true);

            setError("");
            setMessage("");


            await approveSOCCase(
                incidentId,
                analyst.trim(),
                comment.trim()
            );


            setMessage(
                "Response recommendation approved successfully."
            );


            if (
                onDecisionComplete
            ) {

                await onDecisionComplete();

            }

        } catch (err) {

            console.error(
                "Approval failed:",
                err
            );


            setError(
                err.message
                || "Unable to approve the case."
            );

        } finally {

            setLoading(false);

        }
    };


    // ============================================================
    // REJECT
    // ============================================================

    const handleReject = async () => {

        if (
            !analyst.trim()
        ) {

            setError(
                "Analyst name is required."
            );

            return;
        }


        if (
            !comment.trim()
        ) {

            setError(
                "Please provide a reason for rejection."
            );

            return;
        }


        try {

            setLoading(true);

            setError("");
            setMessage("");


            await rejectSOCCase(
                incidentId,
                analyst.trim(),
                comment.trim()
            );


            setMessage(
                "Response recommendation rejected."
            );


            if (
                onDecisionComplete
            ) {

                await onDecisionComplete();

            }

        } catch (err) {

            console.error(
                "Rejection failed:",
                err
            );


            setError(
                err.message
                || "Unable to reject the case."
            );

        } finally {

            setLoading(false);

        }
    };


    return (

        <section
            className="
                detail-panel
                full-width-panel
                analyst-decision-panel
            "
        >

            <div className="panel-heading">

                <div>

                    <h3>
                        Analyst Decision
                    </h3>


                    <p>
                        Review the SENTINEL-X response
                        recommendation before allowing it
                        to proceed through the simulated
                        response workflow.
                    </p>

                </div>


                <span
                    className={
                        alreadyApproved
                            ? "badge low"
                            : alreadyRejected
                                ? "badge critical"
                                : "badge high"
                    }
                >

                    {
                        alreadyApproved
                            ? "APPROVED"
                            : alreadyRejected
                                ? "REJECTED"
                                : "AWAITING REVIEW"
                    }

                </span>

            </div>


            <div className="analyst-safety-banner">

                <strong>
                    Simulation Mode
                </strong>

                <span>
                    Approval does not execute a real
                    endpoint response in the current
                    prototype.
                </span>

            </div>


            {
                error
                && (

                    <div className="analyst-message error">

                        {error}

                    </div>

                )
            }


            {
                message
                && (

                    <div className="analyst-message success">

                        {message}

                    </div>

                )
            }


            <div className="analyst-form-grid">

                <div>

                    <label>
                        Analyst
                    </label>


                    <input
                        type="text"
                        value={
                            analyst
                        }
                        disabled={
                            loading
                            || decisionCompleted
                        }
                        onChange={
                            (
                                event
                            ) =>
                                setAnalyst(
                                    event.target.value
                                )
                        }
                        placeholder="SOC Analyst"
                    />

                </div>


                <div>

                    <label>
                        Comment / Rejection Reason
                    </label>


                    <textarea
                        value={
                            comment
                        }
                        disabled={
                            loading
                            || decisionCompleted
                        }
                        onChange={
                            (
                                event
                            ) =>
                                setComment(
                                    event.target.value
                                )
                        }
                        placeholder="Add analyst notes..."
                        rows="4"
                    />

                </div>

            </div>


            <div className="analyst-action-row">

                <button
                    className="analyst-approve-button"
                    disabled={
                        loading
                        || decisionCompleted
                    }
                    onClick={
                        handleApprove
                    }
                >

                    {
                        loading
                            ? "Processing..."
                            : "Approve Recommendation"
                    }

                </button>


                <button
                    className="analyst-reject-button"
                    disabled={
                        loading
                        || decisionCompleted
                    }
                    onClick={
                        handleReject
                    }
                >

                    Reject Recommendation

                </button>

            </div>


            {
                decisionCompleted
                && (

                    <div className="analyst-completed">

                        Analyst decision has already been
                        recorded for this incident.

                    </div>

                )
            }

        </section>
    );
}


export default AnalystDecisionPanel;