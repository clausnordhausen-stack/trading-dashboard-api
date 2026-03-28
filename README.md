# Trading Systems Dashboard

Mobile and desktop control interface for algorithmic trading systems.

Built with Flutter. Connected to the Signal Agent API.

---

## Overview

This dashboard is not a trading app.

It is a **control and monitoring interface** for automated trading systems.

The app allows users to:

* monitor system status in real time
* track trades and performance
* control risk exposure
* manage multiple trading accounts
* receive alerts and system signals

---

## Core Philosophy

The dashboard follows the same principle as the backend:

Trading systems must be:

* controlled
* transparent
* structured

This app does not execute trades.

It provides **visibility and control over automated execution systems**.

---

## Architecture

Flutter App (Frontend)
↓
REST API (Signal Agent API)
↓
Trading Systems (MT5 Expert Advisors)

---

## Key Features

### Dashboard

* Real-time system overview
* Account selection
* KPI visualization
* System status indicators

---

### Activity Monitoring

* Trade history
* Signal tracking
* Execution logs
* Account-based filtering

---

### Risk Control

* Gate level display (GREEN / YELLOW / RED)
* Risk exposure overview
* Drawdown tracking

---

### Alerts & Status

* Heartbeat monitoring (EA online/offline)
* System alerts
* API connectivity status

---

### Multi-Account Support

* Switch between accounts
* Independent system tracking
* Scalable architecture

---

## API Integration

The app connects to:

Signal Agent API

Example:

https://signal-agent-api.onrender.com

---

## Authentication

* JWT-based login
* Secure token storage via flutter_secure_storage
* Auto-login support

---

## Project Structure

lib/

* app/ → app state & session
* service/ → API communication
* features/ → UI modules

  * dashboard/
  * activity/
  * alerts/
* domain/ → models (e.g. Trade)

---

## Setup

### Requirements

* Flutter SDK
* Dart SDK
* Windows / macOS / Web

---

### Install dependencies

flutter pub get

---

### Run app

flutter run

---

### Web build

flutter build web

---

## Configuration

API base URL is defined in:

lib/service/api_service.dart

Example:

const baseUrl = "https://signal-agent-api.onrender.com";

---

## Environment

Typical backend connection:

* Hosted on Render
* FastAPI backend
* SQLite / PostgreSQL
* JWT authentication

---

## Use Case

Designed for:

* EA traders (MT5)
* multi-account setups
* mobile system monitoring
* risk-controlled trading environments

---

## Positioning

Built with a mindset:

* clarity over complexity
* control over automation hype
* structured decision systems

Target users:

* professional traders
* system developers
* capital-controlled environments

---

## Important Notice

This application:

* does NOT execute trades
* does NOT provide financial advice
* does NOT guarantee profits

It is a control interface only.

---

## Roadmap

* push notifications
* advanced KPI charts
* account management UI
* AI insights integration
* mobile-first optimization

---

## Author

Claus Nordhausen
claus.digital

---

## License

Private / Proprietary
