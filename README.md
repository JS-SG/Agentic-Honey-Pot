# Honeypot API

## Description
This honeypot API is designed to interact with scammers, keep them engaged in conversation, and safely extract useful intelligence such as phone numbers, bank accounts, UPI IDs, emails, and phishing links.
The system detects scam behavior using rule-based analysis and conversation context, and submits the final result to the evaluation server.

## Tech Stack
Language/Framework: Python, FastAPI
Key libraries:
- FastAPI (API framework)
- Requests (callback submission)
- Regex (pattern extraction)
- LLM/AI models used: Lightweight persona-based reply generator (Mistralai) for realistic engagement

## Setup Instructions
1. Clone the repository
2. Install dependencies
   pip install -r requirements.txt
3. Set environment variables
   HONEYPOT_API_KEY = <key>
   MISTRAL_API_KEY=<key>
4. Run the application
   uvicorn main:app --reload

## API Endpoint
- URL: https://agentic-honey-pot-6koz.onrender.com/honeypot
- Method: POST
- Authentication: x-api-key header

## Approach
Scam Detection: 
  1. Each incoming message is analyzed using keyword and pattern detection.
  2. The system checks for:
   - Urgent language
   - Requests for money or OTP
   - Account threats
   - Impersonation tactics
  3. If suspicious behavior is detected, the session is marked as a scam.
Intelligence Extraction:
  1. The system extracts and stores:
    - Phone numbers
    - Bank account numbers
    - UPI IDs
    - Email addresses
    - Phishing links
    - Suspicious keywords
  2. This data is stored per session and sent in the final report.
Engagement Strategy:
  1. The honeypot uses a friendly and cooperative persona.
  2. It asks clarification questions and verification requests.
  3. This encourages the scammer to:
    - Share more details
    - Provide payment information
    - Reveal contact channels
    - The conversation continues until:
    - Enough intelligence is collected, or Maximum conversation turns are reached.
