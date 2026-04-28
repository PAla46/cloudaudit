import json
import csv
import sys
from datetime import datetime
from typing import List, Optional, Dict


COMPLIANCE_FILES = {
    "cis": "compliance/aws/cis_aws.json",
}


def load_compliance_mapping(framework: str = "cis") -> Dict:
    """Load compliance mapping from JSON file"""
    filepath = COMPLIANCE_FILES.get(framework, f"compliance/aws/{framework}_aws.json")
    try:
        with open(filepath) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def get_requirement_mapping(check_id: str, framework: str = "cis") -> List[Dict]:
    """Find which compliance requirements map to a check"""
    mapping = load_compliance_mapping(framework)
    requirements = mapping.get("Requirements", [])
    
    matched = []
    for req in requirements:
        if check_id in req.get("Checks", []):
            matched.append({
                "requirement_id": req.get("Id"),
                "description": req.get("Description"),
                "section": req.get("Attributes", {}).get("Section", ""),
                "profile": req.get("Attributes", {}).get("Profile", ""),
                "assessment_status": req.get("Attributes", {}).get("AssessmentStatus", ""),
            })
    
    return matched


class ComplianceCSVOutput:
    def __init__(self):
        self.framework = "CIS"
    
    def write(self, findings: List, filename: Optional[str] = None, account_id: str = "", framework: str = "cis") -> str:
        mapping = load_compliance_mapping(framework)
        requirements = mapping.get("Requirements", [])
        
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        columns = [
            "PROVIDER", "DESCRIPTION", "ACCOUNTID", "REGION", "ASSESSMENTDATE",
            "REQUIREMENTS_ID", "REQUIREMENTS_DESCRIPTION",
            "REQUIREMENTS_ATTRIBUTES_SECTION", "REQUIREMENTS_ATTRIBUTES_PROFILE",
            "REQUIREMENTS_ATTRIBUTES_ASSESSMENTSTATUS",
            "STATUS", "STATUSEXTENDED", "RESOURCEID", "RESOURCENAME",
            "CHECKID", "MUTED", "FRAMEWORK", "NAME"
        ]
        
        rows = []
        for finding in findings:
            data = finding.as_dict() if hasattr(finding, "as_dict") else {
                "check_id": finding.check_id,
                "status": finding.status,
                "status_extended": finding.status_extended,
                "resource_id": finding.resource_id,
                "region": getattr(finding, "region", "us-east-1"),
            }
            
            check_id = data.get("check_id", "")
            status = data.get("status", "")
            
            matched_requirements = [
                req for req in requirements 
                if check_id in req.get("Checks", [])
            ]
            
            if not matched_requirements:
                rows.append({
                    "PROVIDER": "aws",
                    "DESCRIPTION": mapping.get("Description", ""),
                    "ACCOUNTID": account_id,
                    "REGION": data.get("region", "us-east-1"),
                    "ASSESSMENTDATE": timestamp,
                    "REQUIREMENTS_ID": "",
                    "REQUIREMENTS_DESCRIPTION": f"Check {check_id} not mapped to {framework}",
                    "REQUIREMENTS_ATTRIBUTES_SECTION": "",
                    "REQUIREMENTS_ATTRIBUTES_PROFILE": "",
                    "REQUIREMENTS_ATTRIBUTES_ASSESSMENTSTATUS": "",
                    "STATUS": "MANUAL",
                    "STATUSEXTENDED": check_id,
                    "RESOURCEID": "",
                    "RESOURCENAME": account_id,
                    "CHECKID": check_id,
                    "MUTED": "False",
                    "FRAMEWORK": mapping.get("Framework", framework.upper()),
                    "NAME": mapping.get("Name", "")
                })
            else:
                for req in matched_requirements:
                    attrs = req.get("Attributes", {})
                    rows.append({
                        "PROVIDER": "aws",
                        "DESCRIPTION": mapping.get("Description", ""),
                        "ACCOUNTID": account_id,
                        "REGION": data.get("region", "us-east-1"),
                        "ASSESSMENTDATE": timestamp,
                        "REQUIREMENTS_ID": req.get("Id", ""),
                        "REQUIREMENTS_DESCRIPTION": req.get("Description", ""),
                        "REQUIREMENTS_ATTRIBUTES_SECTION": attrs.get("Section", ""),
                        "REQUIREMENTS_ATTRIBUTES_PROFILE": attrs.get("Profile", ""),
                        "REQUIREMENTS_ATTRIBUTES_ASSESSMENTSTATUS": attrs.get("AssessmentStatus", ""),
                        "STATUS": "PASS" if status == "PASS" else "FAIL",
                        "STATUSEXTENDED": data.get("status_extended", ""),
                        "RESOURCEID": data.get("resource_id", ""),
                        "RESOURCENAME": data.get("resource_id", ""),
                        "CHECKID": check_id,
                        "MUTED": "False",
                        "FRAMEWORK": mapping.get("Framework", framework.upper()),
                        "NAME": mapping.get("Name", "")
                    })
        
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=columns, delimiter=';')
        writer.writeheader()
        writer.writerows(rows)
        
        csv_str = output.getvalue()
        
        if filename:
            with open(filename, "w", newline="", encoding="utf-8") as f:
                f.write(csv_str)
        
        return csv_str


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
            
            check_id = data.get("check_id", "")
            compliance = get_requirement_mapping(check_id)
            compliance_str = ", ".join([r.get("requirement_id", "") for r in compliance])
            
            row = {
                "AUTH_METHOD": "profile",
                "TIMESTAMP": timestamp,
                "ACCOUNT_UID": account_id,
                "ACCOUNT_NAME": "",
                "ACCOUNT_EMAIL": "",
                "ACCOUNT_ORGANIZATION_UID": "",
                "ACCOUNT_ORGANIZATION_NAME": "",
                "ACCOUNT_TAGS": "",
                "FINDING_UID": f"{check_id}-{account_id}-{data.get('region', 'us-east-1')}-{data.get('resource_id', '')}",
                "PROVIDER": "aws",
                "CHECK_ID": check_id,
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
                "COMPLIANCE": compliance_str,
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
        
        findings_with_compliance = []
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
            
            check_id = data.get("check_id", "")
            compliance = get_requirement_mapping(check_id)
            data["compliance"] = compliance
            findings_with_compliance.append(data)
        
        output = {
            "version": self.version,
            "timestamp": timestamp,
            "count": len(findings),
            "account_id": account_id,
            "findings": findings_with_compliance
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
                "severity": f.check_metadata.Severity,
                "service": f.check_metadata.ServiceName,
                "region": getattr(f, "region", ""),
                "arn": getattr(f, "resource_arn", ""),
            }
            
            check_id = data.get("check_id", "")
            compliance = get_requirement_mapping(check_id)
            compliance_str = ", ".join([r.get("requirement_id", "") for r in compliance])
            
            check_title = ""
            risk = ""
            remediation = ""
            
            if hasattr(f, "check_metadata"):
                check_title = f.check_metadata.CheckTitle
                risk = f.check_metadata.Risk
                if f.check_metadata.Remediation:
                    remediation = f.check_metadata.Remediation.get("Recommendation", {}).get("Text", "")
            
            status_class = "bg-success-custom" if data.get("status") == "PASS" else "bg-danger" if data.get("status") == "FAIL" else "bg-warning"
            
            row = f"""<tr>
                <td>{data.get('check_id', '')}</td>
                <td class="{status_class}">{data.get('status', '')}</td>
                <td>{data.get('resource_id', '')}</td>
                <td>{data.get('severity', '').upper()}</td>
                <td>{data.get('service', '')}</td>
                <td>{data.get('region', '')}</td>
                <td>{check_title}</td>
                <td>{compliance_str}</td>
                <td>{data.get('status_extended', '')}</td>
                <td>{risk[:100]}...<br/>{remediation[:100]}...</td>
            </tr>"""
            rows.append(row)
        
        critical_count = sum(1 for f in findings if (hasattr(f, "check_metadata") and f.check_metadata.Severity == "critical") or (hasattr(f, "severity") and f.severity == "critical"))
        high_count = sum(1 for f in findings if (hasattr(f, "check_metadata") and f.check_metadata.Severity == "high") or (hasattr(f, "severity") and f.severity == "high"))
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <style>
        .bg-success-custom {{background-color: #98dea7 !important;}}
        .bg-danger {{background-color: #f28484 !important;}}
        .bg-warning {{background-color: #f5c518 !important;}}
        .table-wrap {{overflow-x: auto;}}
    </style>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css" crossorigin="anonymous" />
    <link rel="stylesheet" href="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.25/b-1.7.1/sp-1.4.0/sl-1.3.3/datatables.min.css" />
    <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.10.0/css/all.css" crossorigin="anonymous" />
    <style>
        .dataTable {{font-size: 13px;}}
        .container-fluid {{font-size: 14px;}}
        .float-left {{ float: left !important; max-width: 100%; }}
        td {{max-width: 300px; word-wrap: break-word;}}
    </style>
    <title>CloudAudit - Cloud Security Report</title>
</head>
<body>
    <div class="container-fluid">
        <div class="row mt-3 mb-3">
            <div class="col-md-3">
                <img src="https://raw.githubusercontent.com/prowler-cloud/prowler/dc7d2d5aeb92fdf12e8604f42ef6472cd3e8e889/docs/img/prowler-logo-black.png" alt="CloudAudit Logo" style="width:150px;"/>
            </div>
            <div class="col-md-9">
                <h2>CloudAudit Security Report</h2>
            </div>
        </div>
        
        <div class="row mt-3">
        <div class="col-md-3">
            <div class="card">
            <div class="card-header bg-primary text-white">Report Information</div>
            <ul class="list-group list-group-flush">
                <li class="list-group-item"><b>Tool:</b> CloudAudit 0.1.0</li>
                <li class="list-group-item"><b>Provider:</b> AWS</li>
                <li class="list-group-item"><b>Date:</b> {timestamp}</li>
                <li class="list-group-item"><b>Account ID:</b> {account_id}</li>
                <li class="list-group-item"><b>Framework:</b> CIS AWS Foundations</li>
            </ul>
            </div>
        </div>
        <div class="col-md-9">
            <div class="card">
            <div class="card-header bg-primary text-white">Executive Summary</div>
            <div class="row text-center">
                <div class="col-md-3">
                    <div class="card bg-danger text-white mb-3">
                        <div class="card-body">
                            <h2 class="mb-0">{fail_count}</h2>
                            <small>FAIL</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-success-custom text-white mb-3">
                        <div class="card-body">
                            <h2 class="mb-0">{pass_count}</h2>
                            <small>PASS</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-warning mb-3">
                        <div class="card-body">
                            <h2 class="mb-0">{unknown_count}</h2>
                            <small>UNKNOWN</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-primary text-white mb-3">
                        <div class="card-body">
                            <h2 class="mb-0">{len(findings)}</h2>
                            <small>TOTAL</small>
                        </div>
                    </div>
                </div>
            </div>
            <div class="row text-center mt-2">
                <div class="col-md-4">
                    <span class="badge badge-danger">{critical_count} Critical</span>
                </div>
                <div class="col-md-4">
                    <span class="badge badge-warning">{high_count} High</span>
                </div>
                <div class="col-md-4">
                    <span class="badge badge-info">{fail_count + pass_count + unknown_count - critical_count - high_count} Others</span>
                </div>
            </div>
            </div>
        </div>
        </div>
        
        <div class="row mt-3">
        <div class="col-md-12">
            <div class="card">
            <div class="card-header bg-secondary text-white">Security Findings</div>
            <div class="table-wrap">
            <table id="table" class="table table-striped table-hover dataTable" style="width:100%">
            <thead>
                <tr>
                    <th>Check ID</th>
                    <th>Status</th>
                    <th>Resource ID</th>
                    <th>Severity</th>
                    <th>Service</th>
                    <th>Region</th>
                    <th>Check Title</th>
                    <th>Compliance</th>
                    <th>Status Extended</th>
                    <th>Risk/Remediation</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
            </table>
            </div>
            </div>
        </div>
        </div>
        
        <div class="row mt-3 mb-5">
        <div class="col-md-12 text-center text-muted">
            <small>Generated by CloudAudit | CIS AWS Foundations Benchmark</small>
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
                buttons: ['copy', 'csv', 'excel', 'pdf'],
                order: [[3, 'desc'], [0, 'asc']],
                pageLength: 50,
                scrollX: true
            }});
        }});
    </script>
</body>
</html>"""
        
        if filename:
            with open(filename, "w") as f:
                f.write(html)
        
        return html