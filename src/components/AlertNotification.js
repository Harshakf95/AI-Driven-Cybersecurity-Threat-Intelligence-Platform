import React from "react";

const AlertNotification = ({ severity, title, description }) => {
  return (
    <div className={`alert alert-${severity}`}>
      <div>
        <span className="alert-title">{title}</span>
        <p className="alert-description">{description}</p>
      </div>
      <button className="btn btn-dismiss">Dismiss</button>
    </div>
  );
};

export default AlertNotification;