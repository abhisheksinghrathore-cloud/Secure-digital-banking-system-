"""
Bank-staff tools (run on the server, never exposed over the web).

  python admin_tools.py unlock <acc_no>          unlock an account locked by wrong PINs
  python admin_tools.py reset-device <acc_no>    forget the trusted device after verifying the customer
  python admin_tools.py requests [status]        list service requests
  python admin_tools.py set-status <id> <status> e.g. Approved / Rejected / In review
"""
import json
import sys
import time

import app as bank


def main():
    a = sys.argv[1:]
    if len(a) >= 2 and a[0] == "unlock":
        print("unlocked" if bank.admin_unlock(int(a[1])) else "no such account")
    elif len(a) >= 2 and a[0] == "reset-device":
        print("device reset (customer's next verified login binds a new device)"
              if bank.admin_reset_device(int(a[1])) else "no such account")
    elif a and a[0] == "requests":
        for r in bank.admin_list_requests(a[1] if len(a) > 1 else None):
            details = "; ".join(f"{d['label']}: {d['value']}" for d in json.loads(r["details"]))
            print(f"#{r['id']} acc {r['acc_no']} [{r['status']}] {r['type']} - {details} "
                  f"({time.strftime('%Y-%m-%d %H:%M', time.localtime(r['created_at']))})")
    elif len(a) >= 3 and a[0] == "set-status":
        print("updated" if bank.admin_set_request_status(int(a[1]), " ".join(a[2:])) else "no such request")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
