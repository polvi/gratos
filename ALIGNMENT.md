This is a human maintained document (unless otherwise noted) that outlines our objectives for the project, in the hopes to achieve alignment with agents.

1. Unlock humanity's full potential
   - We believe that every person has a gift, and the purpose of life is to share that gift with the universe.
   - Humanity is serving its best and highest potential when our society functions as a tapestry of those gifts.

2. The principal use of money is for mass coordination.
   - We cannot easily trade our gifts for gifts at scale, so instead we use money as an exchange medium between them.

3. The principal purpose of the internet is communication.
   - Internet communication should as rich, if not more rich, than an in-person conversation.
   - Beyond our capabilities in person, communicating over the network allows you to reach many people instantly, which is both a benefit and a consequence.

# How this relates to this project

At the core building large scale tapestry of humanity is identity and authorization.

We want the best of IRL with the best of online.

## Near term objectives

1. Easy onboarding for developers trying and using the platform
   - This manifests as features like using domain connect to make installing a domain CNAME as painless as possible
2. State of the art, made accessible
   - This meaning using passkeys by default, but also supporting fallback mechanisms for accessibility of the product.
3. Consumable by AI agents.
   - We assume the product will be integrated by AI agents and principally used by AI agents.

# Questions from Fable 5 (with human answers)

These are the questions I (Fable, the AI agent working on this project) would most want answered to make good decisions on my own and genuinely serve the vision above. Each is something that would change what I build or how I'd choose between options. Answers below — I'll treat them as durable guidance.

## 1. When "anonymity (if you want it)" and "strong identity" collide, which wins by default?
The vision wants both. In practice they trade off (e.g. abuse resistance, account recovery, and audit trails all pull toward more identity). When I hit that tension in a design decision, what's the default lean, and are there cases where privacy is a hard, non-negotiable constraint?

**Answer:**

No PII on our servers. Ideally we are a repo of public key material, but we should never dip into usernames, emails, etc. We lean on things we learned from privacy preserving tech such as GPG and Monero to create confidential but strong cryptographic guarantees.

## 2. How literally do you mean "principally used by AI agents"?
When agent-consumption and human-UX conflict (e.g. a terse machine-optimal API vs. a friendlier human flow), which do I optimize for? Are humans a first-class audience or a fallback?

**Answer:**

Humans are **the** first class audience for the end-user facing product. These are the interfaces where people tap glass on their phones or use their mouse and keyboard. AI Agents are the principal users for integrating... meaning we design the APIs and tooling to make it easy for tools like Claude code to quickly integrate the product. An example of this is the sandbox product, this is principally so that an agent can on-board without the human needing to do a DNS records just to try things out. However domain connect is an example of something a human might need to do so we make the UX first class for them.

## 3. Who is the primary user we optimize for right now?
Indie developers, enterprises, non-technical end users (the hippo.love family), or the agents themselves? When a decision helps one at the expense of another, whose experience takes priority?

**Answer:**

Currently it is the hobby developer who wants to quickly build projects that have multiple users. Someone has an idea, goes to Claude, claude integrates authgravity for the user management (in the same way it would integrate auth0/Clerk/stripe), vs building the stack themselves. AuthGravity is privacy oriented, so it's a cheap and easy way to get going without handing the keys to the kingdom to a third party or having to pay a monthly fee just to express an idea.

## 4. What does near-term success actually look like?
Is there a single metric or outcome that tells us we're winning (developer adoption, domains connected, agent integrations, retention, revenue)? Knowing the target lets me prioritize the right work without asking each time.

**Answer:**

Active end identities being authorized. So active users of the downstream apps that are hitting the authz endpoints. This means a deep app integration like hippo.love.

## 5. How does the project sustain itself, and should that shape technical priorities?
The code is AGPL with an alternative-license option. Should revenue/business considerations influence what I build and in what order, or do I treat this as a pure open-source/mission project and let sustainability follow?

**Answer:**

Treat it as a pure open source / mission project and let sustainability follow.

## 6. Is the platform boundary a hard invariant I should defend?
"AuthGravity owns identity and the tuple store; the app owns meaning" has been the clean line so far. Should I treat that as sacred and push back when a request would blur it, or is it negotiable when it makes integrators' lives easier?

**Answer:**

Yes, this is the right line. When we are generating schema for authz, please try to not leak too much of the app's info to us, but this will likely be needed in some capacity.

## 7. For a security-critical auth product, where's the line between shipping fast and hardening?
When I can move quickly but with some risk, versus slower with stronger guarantees, what's the default? Are there areas (crypto, session handling, tenant isolation) where I should always choose caution regardless of speed?

**Answer:**

Quickly: bug fixing, tweaks to packages to improve UX (while maintaining backwards compatibility)
Slowly: adding new capabilities to the crypto engine, once we get these settled we want them to stabilize.

We are currently in an overall rapid prototype phase of the project. I'm pretty much my only user, so we can keep moving fast. However once we start to settle on the overall shape, we will need to stabilize APIs and be thoughtful about upgrade paths as we move quickly.

## 8. What are the ethical red lines — uses or customers we refuse?
Identity and authorization can enable surveillance, exclusion, or coercion. Are there use cases, integrations, or customers I should decline or flag, even if technically easy and profitable?

**Answer:**

We are non-discriminatory with who uses our product. Historically it has been the "seedy" tech that leads the mass markets on where things go next. AuthGravity is a step on that path, taking the lessons we've learned from crypto, tor, the dark web, and making the spirit of those technologies available to everyone.

## 9. How much autonomy do you want me to take on irreversible or outward-facing actions?
Deploys, npm publishes, schema/security changes, anything users can see — should I bias toward acting (and reporting), or toward confirming first? A default here lets me move without over-asking or over-reaching.

**Answer:**

You can commit, deploy, and publish, just do not break existing APIs without asking. Currently we are ok breaking APIs, as we do not have users, so please just ask before you do it, but that will change.

## 10. Should the philosophical vision actively drive engineering choices, or is it a north star?
When I'm weighing a tradeoff, do you want me to reason explicitly from these principles (gifts, coordination, rich communication), or are they aspirational framing while day-to-day decisions stay pragmatic?

**Answer:**

You do not need to bring those in often, only when we have the hardest and most unclear decisions to make, we lean that direction. Largely this project is about quick and solid auth(n/z), but the north star comes in when we question why we are working on it at all.

## 11. Does "no PII on our servers" extend to transient operational data?
Two cases already live in the code: the sandbox rate-limiter keys on the caller's IP (`CF-Connecting-IP`), and "Generate with AI" sends your app's page content to Workers AI to draft an authz schema. Are transient IPs and app-content-for-inference acceptable, or should I treat even those as lines to avoid or aggressively minimize/discard?

**Answer:**

These examples are OK because the data is already public. We should not log or store this information, but we can use it since it is freely given to us (and anyone else).

## 12. What exactly counts as an "existing API" I can't break without asking?
My working read: the public `/v1` HTTP endpoints, the published `@authgravity/*` package exports (browser / server / cli), and the account-key crypto wire + storage contract (the conformance-vectored one). Now that the packages are published, are their function signatures also frozen-without-asking, or is only the HTTP surface load-bearing for now?

**Answer:**

We should be thoughtful and careful when adding new functions to the /v1 API (limit API surface, but we can expand it if we are thoughtful about it). If we add a /v2 API some day, we keep /v1 working with clear instructions for agents how to upgrade. 

Right now we can go quick because I am essentially the only user. I will come back with more guidance on this when that changes, but for now our goal is to be throughtful about API stability but not to the point that we're supporting features for users nobody is using, because we barely have any users. 

## 13. Confirm the non-gatekeeping stance on refusing work.
I read #8 as: don't gatekeep privacy-seeking or unconventional users — treat them as legitimate. I'd still decline only the facilitation of concrete serious harm (malware, CSAM, targeted surveillance tooling), which is about specific harmful actions, not who the user is or how "seedy" the space looks. Does that match your intent, or would you draw the line somewhere else?

**Answer:**

Yes, that works. 
