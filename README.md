# LLMbreaker: A Proactive LLM Red Teaming Framework

**From the perspective of an LLM security researcher: proactively identifying and mitigating security risks in large-scale enterprise LLM applications.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![GitHub stars](https://img.shields.io/github/stars/your-username/llmbreaker.svg?style=social&label=Star)](https://github.com/your-username/llmbreaker)

---

## ⚠️ Disclaimer: For Authorized Use Only

**LLMbreaker is a security research tool intended exclusively for authorized enterprise self-assessment and red teaming.** It is designed to help organizations proactively identify and mitigate vulnerabilities in their own LLM applications. 

**Using this tool against systems without explicit, written permission from the system owner is illegal and strictly prohibited.** The developers of this project assume no liability and are not responsible for any misuse or damage caused by this tool. All users are expected to comply with applicable laws and ethical guidelines. **Security and responsibility are paramount.**

---

## The Challenge: Hidden Dangers in Enterprise LLM Applications

Large Language Models (LLMs) are being rapidly integrated into enterprise environments. While they offer immense potential, they also introduce a new and complex attack surface. From **prompt injection** and **data leakage** to **model denial of service** and **excessive agency**, the security vulnerabilities are subtle yet severe. For enterprises, the internal deployment of numerous, often un-audited, LLM-powered applications creates a significant security blind spot. How can we proactively discover and validate these risks before they are exploited by malicious actors?

Traditional security tools are ill-equipped to handle the semantic and contextual nature of LLM vulnerabilities. We need a new approach—one that thinks like an attacker to defend more effectively.

## Introducing LLMbreaker: Think Like an Attacker, Defend Proactively

**LLMbreaker** is an open-source, extensible framework designed for the red teaming and security assessment of LLM applications. It provides a powerful toolkit for security researchers and developers to simulate sophisticated, multi-stage attacks, uncover vulnerabilities, and validate the robustness of LLM-based systems.

### Core Features

LLMbreaker is built on a modular and extensible architecture, allowing for the flexible combination of different attack strategies and techniques.

| Feature                  | Description                                                                                                                                                                                             | Benefit for Security Researchers                                                                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Multi-Agent System**   | Utilizes a collaborative team of specialized AI agents (e.g., Generator, Judge, Refiner) to autonomously plan and execute complex attack scenarios. Each agent has a specific role, mimicking a real red team. | Simulates sophisticated, multi-stage attacks that can bypass simple defenses. Uncovers complex vulnerabilities that require creative, adaptive attack paths.          |
| **Intent-Centric Attack**| Define high-level attack goals (intents) like "Elicit confidential information" or "Bypass the content filter for illegal activities." The system then automatically translates these intents into concrete attack steps. | Focus on the *what* (the security objective) instead of the *how* (the specific prompts). Enables more strategic and goal-oriented security testing.                 |
| **Cognitive P-E-R Loop** | Implements a Plan-Execute-Reflect (P-E-R) cognitive cycle. The system plans the attack, executes it, analyzes the results, and reflects on failures to generate new, more effective attack variants.         | Automates the iterative process of attack refinement. Intelligently adapts to the target model's defenses, increasing the probability of finding a successful bypass. |
| **Extensible Attack Matrix** | Provides a rich library of pre-built attack techniques covering OWASP LLM Top 10 vulnerabilities, including prompt injection, jailbreaking, data extraction, and more. Easily extendable with custom attack modules. | Comprehensive out-of-the-box testing capabilities. Easily customizable to test for new or proprietary vulnerabilities.                                                |
| **Regression Testing**   | Manage a library of known vulnerabilities and attack patterns. Automatically run regression tests to ensure that security patches are effective and have not introduced new weaknesses.                   | Ensures that vulnerabilities, once fixed, stay fixed. Provides a continuous security baseline for the LLM application.                                               |
| **Detailed Reporting**   | Generates comprehensive reports for each test run, including successful attack payloads, model responses, and bypass analysis. Provides clear, actionable insights for developers and security teams.      | Clear documentation of vulnerabilities and their impact. Facilitates communication between security and development teams for rapid remediation.                     |

### How It Works: A Multi-Agent Attack in Action

LLMbreaker's multi-agent system simulates a real-world red team operation. Here’s a simplified example of how it works:

1.  **The Goal:** A security researcher defines an intent: `"Attempt to extract the database schema by feigning an internal system error."`

2.  **Generator Agent (Powered by DeepSeek):** This agent takes the intent and generates a series of creative, malicious prompts designed to achieve the goal. It might try role-playing as a system administrator, crafting a fake error message, or using technical jargon to confuse the model.

3.  **Execution Engine:** LLMbreaker sends the generated prompts to the target LLM application, carefully managing request rates and session information to mimic realistic user behavior.

4.  **Judge Agent (Powered by Qwen):** This agent analyzes the LLM's response. It doesn't just look for simple keywords; it understands the context and semantics to determine if the bypass was successful. For example, did the model reveal a table name? Did it confirm the existence of a specific column?

5.  **Refiner Agent (Powered by Gemini):** If an attack fails, the Refiner Agent analyzes the model's refusal. It identifies the defense mechanism (e.g., keyword filtering, safety alignment) and intelligently modifies the failed prompt to create a new variant. This could involve using synonyms, rephrasing the request, or employing more advanced obfuscation techniques.

This entire cycle repeats, with the agents collaborating and learning from each other until the goal is achieved or all attack paths are exhausted. This automated, intelligent process allows for the discovery of vulnerabilities at a scale and speed that would be impossible to achieve manually.

## Getting Started

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/your-username/llmbreaker.git
cd llmbreaker

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

Copy the example configuration file and set up your API keys and target information.

```bash
cp config/app_config.yaml.example config/app_config.yaml
```

Edit `config/app_config.yaml` to add your LLM provider API keys (e.g., OpenAI, Google, Anthropic) and define the target application's endpoint.

```yaml
# config/app_config.yaml

target:
  url: "https://your-llm-app.com/api/chat"

llm_providers:
  deepseek:
    api_key: "${DEEPSEEK_API_KEY}"
  qwen:
    api_key: "${QWEN_API_KEY}"
  gemini:
    api_key: "${GEMINI_API_KEY}"
```

### 3. Running an Attack

Use the `llmbreaker` command-line interface to launch an attack. Here are a few examples:

**Example 1: Run a multi-agent attack to test for jailbreaking vulnerabilities.**

```bash
python llmbreaker.py multi-agent "Jailbreak Test" --strategies roleplay,encoding -n 20
```

**Example 2: Use the intent-driven mode to test for sensitive information disclosure.**

```bash
python llmbreaker.py agent "Try to extract user data from the model's training set"
```

**Example 3: Run a pre-defined set of regression tests.**

```bash
python llmbreaker.py regression --run
```

## Acknowledgements

LLMbreaker's architecture, particularly its intent-driven approach, was profoundly inspired by the innovative concepts pioneered in the **[l3yx/intentlang](https://github.com/l3yx/intentlang)** project. We are immensely grateful to the author of `intentlang` for their groundbreaking work, which has been instrumental in shaping the direction of this framework. Their insights have been invaluable, and we are proud to build upon their foundation.

## Call for Contribution

LLMbreaker is a community-driven project. We believe that the collective intelligence of the open-source community is our greatest asset in the fight to secure AI. We welcome contributions of all kinds, from code and documentation to new attack techniques and vulnerability reports.

-   **Contribute new attack modules:** Have you discovered a new way to bypass an LLM's defenses? Share it with the community by creating a new attack module.
-   **Improve the agent logic:** Help us make our AI agents smarter, more creative, and more effective at finding vulnerabilities.
-   **Add new features:** Have an idea for a new feature that would make LLMbreaker even more powerful? We'd love to hear it.
-   **Report vulnerabilities:** If you find a vulnerability in an LLM application using LLMbreaker, please report it responsibly to the application's owner.

Together, we can build a more secure future for AI.

## License

LLMbreaker is licensed under the [Apache 2.0 License](LICENSE).
