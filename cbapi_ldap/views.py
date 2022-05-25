# from jsonrpc import jsonrpc_method

TODO = [
    '',
]

# @jsonrpc_method("ping", authenticated=True)
def ping(request, username, password):
    """Ping - Echo Request

    :returns str: echo_response
    """
    echo_response = "PONG"
    return echo_response

# @jsonrpc_method("todo")
def todo(request):
    """Todo - List ToDo Items

    :returns list: todolist
    """
    return TODO
