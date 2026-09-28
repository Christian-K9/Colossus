def act_I():
    with open("savedsearches.conf", "r", encoding="utf-8") as file:
        for line in file:
            new_line = f"'{line.rstrip("\n")}\n',"
            print(new_line)
def act_II():

    with open("codes.txt", "r", encoding="utf-8") as file:
        for line in file:
            cleaned_line = line.strip()
            words = cleaned_line.split("\t")
            code = words[0]
            keyword = words[1]
            severity = words[2]
            description = f"Windows Code {code} detected: {keyword}"
            title = f"Windows_Log_Event_{code}"

            my_lines = [f'[{title}]\n',
            'action.lookup = 1\n',
            'action.lookup.append = 1\n',
            'action.lookup.filename = windows_events.csv\n',
            'action.webhook.enable_allowlist = 0\n',
            'alert.digest_mode = 0\n',
            'alert.suppress = 0\n',
            'alert.track = 0\n',
            'counttype = number of events\n',
            'cron_schedule = */10 * * * *\n',
            f'description = {keyword}\n',
            'dispatch.earliest_time = -10m\n',
            'dispatch.latest_time = now\n',
            'display.events.fields = ["host","sourcetype"]\n',
            'display.general.type = statistics\n',
            'display.page.search.tab = statistics\n',
            'enableSched = 1\n',
            'quantity = 0\n',
            'relation = greater than\n',
            'request.ui_dispatch_app = search\n',
            'request.ui_dispatch_view = search\n',
            f'search = index=* sourcetype="WinEventLog:Security" "EventCode={code}" | eval severity="{severity}" | eval code="{keyword}" | table _time severity code EventCode AccountName Process_ID Source_Network_Address Source_Port\n']

            with open("new_searches.conf", "a") as file:
                        file.writelines(my_lines)
                        file.write("\n")
act_II()
