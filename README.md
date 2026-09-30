# Webhook Lab

A lightweight, secure, and event-driven webhook listener built with Python, Flask, and SQLite inside Termux.

## Features

- **HMAC-SHA256 Authentication:** Validates incoming payload signatures against a shared secret to prevent unauthorized requests.
- **SQLite Persistence:** Automatically creates a database table and logs authenticated webhook payloads with ISO timestamps.
- **Mobile-First Backend Architecture:** Designed to run efficiently in a lightweight Android Termux environment.

## Quickstart

1. **Clone the repository:**
   ```bash
   git clone git@github.com:DivineChisom/webhook-lab.git
   cd webhook-lab

python -m venv venv
source venv/bin/activate
pip install flask

