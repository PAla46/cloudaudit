import json
import sys
from datetime import datetime
from typing import List, Optional

from lib.check.models import Check_Report


class JSONOutput:
    def __init__(self):
        self.version = "0.1.0"
    
    def write(self, findings: List, filename: Optional[str] = None) -> str:
        output = {
            "version": self.version,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "count": len(findings),
            "findings": [
                f.as_dict() if hasattr(f, "as_dict") else {
                    "check_id": f.check_id,
                    "status": f.status,
                    "status_extended": f.status_extended,
                    "resource_id": f.resource_id,
                    "severity": f.check_metadata.Severity,
                    "service": f.check_metadata.ServiceName,
                    "region": getattr(f, "region", ""),
                    "arn": getattr(f, "resource_arn", ""),
                }
                for f in findings
            ]
        }
        
        json_str = json.dumps(output, indent=2)
        
        if filename:
            with open(filename, "w") as f:
                f.write(json_str)
        
        return json_str


class CSVOutput:
    def __init__(self):
        self.columns = [
            "check_id",
            "status",
            "resource_id",
            "severity",
            "service",
            "region",
            "message"
        ]
    
    def write(self, findings: List, filename: Optional[str] = None) -> str:
        lines = [",".join(self.columns)]
        
        for f in findings:
            if hasattr(f, "as_dict"):
                data = f.as_dict()
            else:
                data = {
                    "check_id": f.check_id,
                    "status": f.status,
                    "resource_id": f.resource_id,
                    "severity": f.check_metadata.Severity if hasattr(f, "check_metadata") else "medium",
                    "service": f.check_metadata.ServiceName if hasattr(f, "check_metadata") else "",
                    "region": getattr(f, "region", ""),
                    "message": f.status_extended,
                }
            
            row = [
                str(data.get(col, "")).replace(",", ";")
                for col in self.columns
            ]
            lines.append(",".join(row))
        
        csv_str = "\n".join(lines)
        
        if filename:
            with open(filename, "w") as f:
                f.write(csv_str)
        
        return csv_str


class HTMLOutput:
    def __init__(self):
        pass
    
    def write(self, findings: List, filename: Optional[str] = None) -> str:
        html = """<!DOCTYPE html>
<html>
<head>
    <title>CloudAudit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .PASS { color: green; font-weight: bold; }
        .FAIL { color: red; font-weight: bold; }
        .UNKNOWN { color: orange; }
        .critical { background-color: #ffcccc; }
        .high { background-color: #ffe6cc; }
        .medium { background-color: #ffffcc; }
        .low { background-color: #ccffcc; }
    </style>
</head>
<body>
    <h1>CloudAudit Security Report</h1>
    <p>Generated: {timestamp}</p>
    <p>Total Findings: {count}</p>
    <table>
        <tr>
            <th>Check ID</th>
            <th>Status</th>
            <th>Resource</th>
            <th>Severity</th>
            <th>Service</th>
            <th>Region</th>
            <th>Message</th>
        </tr>
        {rows}
    </table>
</body>
</html>"""
        
        rows = []
        for f in findings:
            if hasattr(f, "as_dict"):
                data = f.as_dict()
            else:
                data = {
                    "check_id": f.check_id,
                    "status": f.status,
                    "resource_id": f.resource_id,
                    "severity": "medium",
                    "service": "",
                    "region": "",
                    "message": f.status_extended,
                }
            
            status_class = data.get("status", "UNKNOWN")
            severity = data.get("severity", "medium")
            
            row = f"""<tr class="{severity}">
                <td>{data.get('check_id', '')}</td>
                <td class="{status_class}">{status_class}</td>
                <td>{data.get('resource_id', '')}</td>
                <td>{severity}</td>
                <td>{data.get('service', '')}</td>
                <td>{data.get('region', '')}</td>
                <td>{data.get('status_extended', '')}</td>
            </tr>"""
            rows.append(row)
        
        html = html.format(
            timestamp=datetime.utcnow().isoformat() + "Z",
            count=len(findings),
            rows="".join(rows)
        )
        
        if filename:
            with open(filename, "w") as f:
                f.write(html)
        
        return html