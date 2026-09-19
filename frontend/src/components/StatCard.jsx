function StatCard({
    title,
    value,
    subtitle,
}) {
    return (
        <div className="stat-card">
            <span className="stat-card-title">
                {title}
            </span>

            <strong className="stat-card-value">
                {value}
            </strong>

            <span className="stat-card-subtitle">
                {subtitle}
            </span>
        </div>
    );
}

export default StatCard;