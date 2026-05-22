from dotenv import load_dotenv
load_dotenv()
from utils import chatbot
import os

print('OPENROUTER_API_KEY set?', bool(os.environ.get('OPENROUTER_API_KEY')))
print('OPENROUTER_API_KEY (masked):', '<set>' if os.environ.get('OPENROUTER_API_KEY') else '<not set>')
try:
    ai = chatbot.ask_openrouter('what is ip')
    print('ask_openrouter returned:', ai is not None)
    if ai:
        print('AI reply (truncated):', ai[:500])
except Exception as e:
    print('ask_openrouter exception:', repr(e))
print('chatbot_reply output (truncated):', chatbot.chatbot_reply('what is ip')[:500])
