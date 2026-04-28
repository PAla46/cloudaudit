import csv
import sys
from datetime import datetime
from typing import List, Optional


class CSVOutput:
    def __init__(self):
        self.columns = [
            "AUTH_METHOD",
            "TIMESTAMP",
            "ACCOUNT_UID",
            "ACCOUNT_NAME",
            "ACCOUNT_EMAIL",
            "ACCOUNT_ORGANIZATION_UID",
            "ACCOUNT_ORGANIZATION_NAME",
            "ACCOUNT_TAGS",
            "FINDING_UID",
            "PROVIDER",
            "CHECK_ID",
            "CHECK_TITLE",
            "CHECK_TYPE",
            "STATUS",
            "STATUS_EXTENDED",
            "MUTED",
            "SERVICE_NAME",
            "SUBSERVICE_NAME",
            "SEVERITY",
            "RESOURCE_TYPE",
            "RESOURCE_UID",
            "RESOURCE_NAME",
            "RESOURCE_DETAILS",
            "RESOURCE_TAGS",
            "PARTITION",
            "REGION",
            "DESCRIPTION",
            "RISK",
            "RELATED_URL",
            "REMEDIATION_RECOMMENDATION_TEXT",
            "REMEDIATION_RECOMMENDATION_URL",
            "REMEDIATION_CODE_CLI",
            "COMPLIANCE",
            "CATEGORIES",
            "NOTES",
            "PROWLER_VERSION",
        ]
    
    def write(self, findings: List, filename: Optional[str] = None, account_id: str = "") -> str:
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        rows = []
        for f in findings:
            data = f.as_dict() if hasattr(f, "as_dict") else {
                "check_id": f.check_id,
                "status": f.status,
                "status_extended": f.status_extended,
                "resource_id": f.resource_id,
                "severity": f.check_metadata.Severity,
                "service": f.check_metadata.ServiceName,
                "region": getattr(f, "region", ""),
                "arn": getattr(f, "resource_arn", ""),
            }
            
            row = {
                "AUTH_METHOD": "profile",
                "TIMESTAMP": timestamp,
                "ACCOUNT_UID": account_id,
                "ACCOUNT_NAME": "",
                "ACCOUNT_EMAIL": "",
                "ACCOUNT_ORGANIZATION_UID": "",
                "ACCOUNT_ORGANIZATION_NAME": "",
                "ACCOUNT_TAGS": "",
                "FINDING_UID": f"{data.get('check_id', '')}-{account_id}-{data.get('region', 'us-east-1')}-{data.get('resource_id', '')}",
                "PROVIDER": "aws",
                "CHECK_ID": data.get("check_id", ""),
                "CHECK_TITLE": "",
                "CHECK_TYPE": "",
                "STATUS": data.get("status", ""),
                "STATUS_EXTENDED": data.get("status_extended", ""),
                "MUTED": "False",
                "SERVICE_NAME": data.get("service", ""),
                "SUBSERVICE_NAME": "",
                "SEVERITY": data.get("severity", "medium").upper(),
                "RESOURCE_TYPE": "",
                "RESOURCE_UID": data.get("resource_id", ""),
                "RESOURCE_NAME": data.get("resource_id", ""),
                "RESOURCE_DETAILS": "",
                "RESOURCE_TAGS": "",
                "PARTITION": "aws",
                "REGION": data.get("region", "us-east-1"),
                "DESCRIPTION": "",
                "RISK": "",
                "RELATED_URL": "",
                "REMEDIATION_RECOMMENDATION_TEXT": "",
                "REMEDIATION_RECOMMENDATION_URL": "",
                "REMEDIATION_CODE_CLI": "",
                "COMPLIANCE": "",
                "CATEGORIES": "",
                "NOTES": "",
                "PROWLER_VERSION": "0.1.0",
            }
            rows.append(row)
        
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=self.columns, delimiter=';')
        writer.writeheader()
        writer.writerows(rows)
        
        csv_str = output.getvalue()
        
        if filename:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                f.write(csv_str)
        
        return csv_str


class JSONOutput:
    def __init__(self):
        self.version = "0.1.0"
    
    def write(self, findings: List, filename: Optional[str] = None, account_id: str = "") -> str:
        import json
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        output = {
            "version": self.version,
            "timestamp": timestamp,
            "count": len(findings),
            "account_id": account_id,
            "findings": [
                f.as_dict() if hasattr(f, "as_dict") else {
                    "check_id": f.check_id,
                    "status": f.status,
                    "status_extended": f.status_extended,
                    "resource_id": f.resource_id,
                    "severity": f.check_metadata.Severity if hasattr(f, "check_metadata") else "medium",
                    "service": f.check_metadata.ServiceName if hasattr(f, "check_metadata") else "",
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


class HTMLOutput:
    def __init__(self):
        pass
    
    def write(self, findings: List, filename: Optional[str] = None, account_id: str = "") -> str:
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        
        pass_count = sum(1 for f in findings if f.status == "PASS" or (hasattr(f, "status") and f.status == "PASS"))
        fail_count = sum(1 for f in findings if f.status == "FAIL" or (hasattr(f, "status") and f.status == "FAIL"))
        unknown_count = sum(1 for f in findings if f.status == "UNKNOWN" or (hasattr(f, "status") and f.status == "UNKNOWN"))
        
        rows = []
        for f in findings:
            data = f.as_dict() if hasattr(f, "as_dict") else {
                "check_id": f.check_id,
                "status": f.status,
                "status_extended": f.status_extended,
                "resource_id": f.resource_id,
                "severity": f.check_metadata.Severity if hasattr(f, "check_metadata") else "medium",
                "service": f.check_metadata.ServiceName if hasattr(f, "check_metadata") else "",
                "region": getattr(f, "region", ""),
                "arn": getattr(f, "resource_arn", ""),
            }
            
            status_class = "bg-success-custom" if data.get("status") == "PASS" else "bg-danger" if data.get("status") == "FAIL" else "bg-warning"
            
            row = f"""<tr>
                <td>{data.get('check_id', '')}</td>
                <td>{data.get('status', '')}</td>
                <td>{data.get('resource_id', '')}</td>
                <td>{data.get('severity', '').upper()}</td>
                <td>{data.get('service', '')}</td>
                <td>{data.get('region', '')}</td>
                <td>{data.get('status_extended', '')}</td>
            </tr>"""
            rows.append(row)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <style>
        .bg-success-custom {{background-color: #98dea7 !important;}}
        .bg-danger {{background-color: #f28484 !important;}}
        .bg-warning {{background-color: #f5c518 !important;}}
    </style>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css" crossorigin="anonymous" />
    <link rel="stylesheet" href="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.25/b-1.7.1/sp-1.4.0/sl-1.3.3/datatables.min.css" />
    <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.10.0/css/all.css" crossorigin="anonymous" />
    <style>
        .dataTable {{font-size: 14px;}}
        .container-fluid {{font-size: 14px;}}
        .float-left {{ float: left !important; max-width: 100%; }}
    </style>
    <title>CloudAudit - Cloud Security Tool</title>
</head>
<body>
    <div class="container-fluid">
        <div class="row mt-3">
        <div class="col-md-4">
            <div class="card">
            <div class="card-header">Report Information</div>
            <ul class="list-group list-group-flush">
                <li class="list-group-item"><b>Version:</b> 0.1.0</li>
                <li class="list-group-item"><b>Parameters used:</b> aws</li>
                <li class="list-group-item"><b>Date:</b> {timestamp}</li>
                <li class="list-group-item"><b>Account ID:</b> {account_id}</li>
            </ul>
            </div>
        </div>
        <div class="col-md-8">
            <div class="card">
            <div class="card-header">Summary</div>
            <ul class="list-group list-group-flush">
                <li class="list-group-item bg-success-custom"><b>PASS:</b> {pass_count}</li>
                <li class="list-group-item bg-danger"><b>FAIL:</b> {fail_count}</li>
                <li class="list-group-item bg-warning"><b>UNKNOWN:</b> {unknown_count}</li>
                <li class="list-group-item"><b>TOTAL:</b> {len(findings)}</li>
            </ul>
            </div>
        </div>
        </div>
        <div class="row mt-3">
        <div class="col-md-12">
            <table id="table" class="table table-striped table-hover dataTable" style="width:100%">
            <thead>
                <tr>
                    <th>Check ID</th>
                    <th>Status</th>
                    <th>Resource</th>
                    <th>Severity</th>
                    <th>Service</th>
                    <th>Region</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
            </table>
        </div>
        </div>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.0.min.js" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
    <script src="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.25/b-1.7.1/sp-1.4.0/sl-1.3.3/datatables.min.js"></script>
    <script>
        $(document).ready(function() {{
            $('#table').DataTable({{
                dom: 'Blfrtip',
                buttons: ['copy', 'csv', 'pdf'],
                order: [[0, 'asc'], [3, 'desc']]
            }});
        }});
    </script>
</body>
</html>"""
        
        if filename:
            with open(filename, "w") as f:
                f.write(html)
        
        return html