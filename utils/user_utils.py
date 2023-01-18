import json
from flask import Response

def response_dict(data=None, status=200, message="", total_count=0, page_number=0):
    """
    Returns a response object for DB searches
    """
    resp_dict = {
        "success": True,
    }
    if data is None:
        data = {}
    if status in [200, 202]:
        resp_dict["data"] = data
        if message:
            if isinstance(data, list):
                resp_dict["message"] = message
            else:
                resp_dict["data"]["message"] = message
    else:
        resp_dict["error"] = message
        resp_dict["success"] = False

    if total_count:
        resp_dict["total_count"] = total_count

    if page_number:
        resp_dict["page_number"] = page_number

    return Response(
        response=json.dumps(obj=resp_dict),
        status=status,
        mimetype="application/json",
        headers=BASE_HEADERS,
    )
