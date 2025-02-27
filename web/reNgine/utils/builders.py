def build_cmd(cmd, options, flags, sep=" "):
    for k,v in options.items():
        if not v:
            continue
        cmd += f" {k}{sep}{v}"

    for flag in flags:
        if not flag:
            continue
        cmd += f" --{flag}"

    return cmd

def generate_gospider_params(custom_header):
    """
    Generate command-line parameters for gospider based on the custom header.

    Args:
        custom_header (dict): Dictionary containing the custom headers.

    Returns:
        str: Command-line parameters for gospider.
    """
    params = []
    for key, value in custom_header.items():
        if key.lower() == 'user-agent':
            params.append(f' -u "{value}"')
        elif key.lower() == 'cookie':
            params.append(f' --cookie "{value}"')
        else:
            params.append(f' -H "{key}:{value}"')
    return ' '.join(params)
