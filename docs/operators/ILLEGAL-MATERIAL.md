# If you see what looks like child sexual abuse material

> **This is not legal advice.** The Faro project is not your lawyer, and the law is different from country to country and state to state. **Operators: have a lawyer check this guidance, and add your own local details, before you rely on it or hand it to allies.**

> **If a child is in danger right now, call your local emergency number** (for example 911 in the US, 999 in the UK, or 112 across the European Union). Do that before anything else in this guide.

**Who this is for:**

- **allies** who see something in Faro that looks like child sexual abuse material (CSAM): sexual images of anyone who might be under 18, or a website name or window title that points to it;
- **operators** (the church, college, group or person running a Faro instance) when an ally tells them about it;
- **safeguarding leads**, pastors and college staff who support either of them.

It covers what not to do, how to report, and what information Faro actually keeps, so you know what evidence exists and who can get to it.

## 1. What not to do

**Don't make or pass on any copy of it.** In particular, don't:

- download or save it;
- take a screenshot, or photograph the screen with a phone;
- copy it, print it, or paste it anywhere;
- forward it or send it to anyone, including the operator, your pastor, a colleague or the police. Reporting sites tell you how to report without sending images;
- show it to anyone else;
- go looking for more, for example by visiting the website named in Faro.

**Why:** in many countries, making or sharing a copy of child sexual abuse material is a crime in itself, even when you only meant to report it. And every copy harms the child again. Hotlines and the police have safe, legal ways to handle it; you don't.

**Don't try to investigate it yourself**, and don't delete anything in Faro (you couldn't anyway, but don't ask anyone else to).

## 2. What to do straight away

1. **Stop looking.** Click **Lock** at the top of the Faro page, then close the page. Faro's page doesn't save what you unlocked: locking clears it, and it is forgotten when you reload or close the page.
2. **Write down what you saw, in words.** Not a picture. Note:
   - the date and time shown on the item in Faro;
   - the member's name and the computer's name;
   - what kind of item it was (for example "Something was flagged" or a daily report);
   - what Faro showed, in your own words: the website name, the app and the window title, typed out as text if you remember them, and a short description of the blurred picture;
   - when you saw it.
3. **Report it** (section 3).
4. **Look after yourself.** Seeing this, or even suspecting it, is upsetting. Talk to someone you trust about how you feel, without describing the image or passing it on.

## 3. How to report

Report to a hotline or the police in your country. You don't need to be sure. Hotlines exist to judge this, and you can usually report without giving your name.

| Where you are | Where to report |
|---|---|
| **United States** | The **CyberTipline** of the National Center for Missing & Exploited Children (NCMEC): online at <https://report.cybertip.org>, or by phone on **1-800-843-5678** (24 hours). You can also contact your local police or the FBI. |
| **United Kingdom** | The **Internet Watch Foundation (IWF)**: <https://www.iwf.org.uk/en/uk-report/>. Reports can be anonymous. If a child is at risk, also contact the police. |
| **Anywhere else** | Your country's national hotline. Most belong to **INHOPE**, the international network of hotlines: on <https://www.inhope.org>, find your country with the drop-down list or the map. You can also contact your local police. |

*[NEEDS A PERSON TO CONFIRM before this guide goes to allies: someone must check these addresses and the NCMEC phone number against the organisations' own websites (missingkids.org, iwf.org.uk and inhope.org), and record the date here.] If one doesn't work, search for the organisation's name and use its official website. Operators: [FILL IN: add any local hotline, police contact or safeguarding contact your people should use].*

**What to tell them:** what you wrote down in section 2. Tell them it came from Faro, an accountability app; that the picture is heavily blurred; and who runs the Faro instance (the operator's name and contact). Section 5 below describes what Faro keeps. You can point them to it.

**Ask them what to do next,** especially before you talk to the member (section 4).

### Duties to report

You may be **required by law** to report, not just allowed to. In many places, clergy, teachers, college staff and others who work with children or young people have that duty, and churches and colleges often have their own safeguarding policy too. [FILL IN: your organisation's safeguarding policy, who your safeguarding lead is, and how to reach them. ASK YOUR LAWYER: who in your organisation has a legal duty to report, to whom, and how quickly.]

## 4. Talking to the member

Faro exists to make honest conversations easier, and the ally guide encourages allies to ask before they assume. **This is different.** Before you talk to the member about it, ask the hotline or the police what they advise. Talking first could, in some cases, put a child at risk or lead to evidence being destroyed.

If you are worried that the member might harm themselves or someone else, contact the emergency services.

## 5. What Faro keeps, and who can see it

This section explains what evidence exists, so that you, the hotline or the police know what to ask for. Faro's design is described in [ARCHITECTURE.md](../ARCHITECTURE.md) (§3.5, §5, §8 and §12).

### There is no clear picture anywhere

Faro never saves a clear screenshot. Not on the member's computer, not on the server, not anywhere. The full picture exists only in the computer's memory for a moment, while Faro checks it and makes a blurred copy, and is then wiped. What Faro keeps of a flagged moment is a **small blurred picture**: about 320 pixels wide, strongly blurred and then pixelated, on the member's computer, before anything is saved or sent. It is made to show the general idea ("a video with a person in it") without the explicit detail. **Nobody can un-blur it**, and there is no setting that keeps clear pictures.

So an ally will usually suspect CSAM from the **context** (a website name, an app, a window title) rather than from the picture itself. Faro's image check rates a screen as explicit or not; it has no "suggestive" rating ([BETA.md §4.2](../BETA.md#42-what-faro-doesnt-flag)), so it misses much borderline content. Its flags say nothing about anyone's age, and Faro doesn't look for child abuse material specifically.

### What a flagged item contains

Each flagged moment, and each daily report, is **encrypted on the member's computer** before it is sent. Inside, it can contain:

- the rating (low, medium or high) and the reasons for it, for example "from what was on screen" or "from the website";
- the app, and the window's title;
- the website's name (for example `example.com`). Faro records only the site's name, not the full page address;
- which account on the computer was in use;
- the blurred picture;
- any note the member added.

### Who can unlock it

Only the **member** and the **allies the member approved**, each with their own passphrase or recovery code, in their own web browser. An ally can only unlock items from after the member approved them.

**The operator can't, with one limit.** The server stores these items, but it never has the keys, and nothing in Faro's server or admin console lets an operator or admin decrypt them. The limit: allies and members unlock items in the Faro web app, which the instance serves. An operator who changed the code the instance sends to browsers could in principle capture a passphrase as it is typed ([ARCHITECTURE.md §5.3](../ARCHITECTURE.md#53-trusting-the-instance-operator)). Don't do that. The Faro project can't either: it runs no central service and has no access to any instance.

What the operator *can* see is metadata: the member's name and email address, their computers' names, who their allies are, and *when* something happened on a computer, what kind of thing it was (for example a flag) and how urgent it was. Not what it was about.

### How long it is kept

Faro deletes old data automatically, once a day, on the instance's schedule. Faro's defaults, which each instance can change:

| What | Default |
|---|---|
| Encrypted flagged items and daily reports, including the blurred pictures | **30 days** after they reach the server |
| Activity records: when something happened, what kind, how urgent | 90 days |
| Alerts | 90 days |

- **This instance's settings:** [FILL IN: your retention periods, from Admin → Settings].
- **A member can shorten** how long their own items are kept, to as little as 7 days. The change only applies to items that arrive after it, and their allies are told.
- **If the member deletes their account**, their allies are emailed at once, and after a 7-day hold everything about them is deleted from the server, including all their encrypted items.
- **Backups** made by the operator hold a copy of the server's data, still encrypted, until those backups are deleted.
- **An ally can't keep anything.** When an item is deleted from the server, it is gone for allies too: Faro says "The details are no longer stored".

So **time matters**. Encrypted items may be deleted within days or weeks. Tell the hotline or police when you saw the item, and tell them the retention periods above.

## 6. For operators

### If an ally tells you

- **Don't ask to see it,** and don't accept a copy if one is offered. Say why (section 1).
- **Point them to this guide** and to the hotline for your country (section 3). You may report too. [FILL IN: your organisation's process, and who decides.]
- **Write down** what the ally told you, when, and what you did.
- **Remember what you can and can't see.** Faro gives you no way to decrypt anything (see the limit in section 5). Don't try, and don't claim you can.

### Don't tip anyone off, and don't destroy anything

Several actions in Faro **always email the member and their allies**. That is by design, so Faro can never be used to monitor anyone secretly. In this situation it matters:

- **Disabling the member's account** emails the member and every ally straight away. Those emails can't be switched off. It also doesn't stop monitoring: the member's computers keep reporting to their allies.
- **Requesting the account's deletion** is the other thing an admin can do to a member's account. It emails the member and everyone in a partnership with them, and after 7 days it **destroys all of the member's encrypted items** on the server. This is the most damaging thing you could do here. **Do not do it** while a report is open.
- Admins have no other way to act on a member's account: they can't remove allies or computers, and they can't see content.

Before you disable an account, request or confirm a deletion, change settings, delete backups, or do anything else that touches the member's data, **ask the police or the hotline, and your lawyer**. Don't delete or change anything once you know about a report.

### What you can give investigators

If the police or a court ask you for information, get legal advice first. [ASK YOUR LAWYER: how you handle such requests, and what you need before you hand anything over.] What you hold is limited to:

- account details: names, email addresses, roles, when accounts were created and last signed in;
- who is whose ally;
- the member's computers: their names, operating system, when they were added, when they last checked in;
- activity records: when something happened on each computer, what kind of thing it was, and how urgent. Not what it was;
- alerts and email delivery records;
- the encrypted items themselves, which only the member and their approved allies can unlock.

Faro doesn't store network (IP) addresses. [FILL IN: if a proxy or tunnel in front of Faro logs them, say so and for how long.]

**Keeping data longer.** Faro deletes encrypted items on the schedule in section 5. It has no way to hold one person's data back from deletion. Lengthening the instance's retention settings does **not** preserve a member's items: a member's own shorter window (as little as 7 days) still applies to what they upload, and it can't be overridden. **Only a backup preserves them.** A backup holds items still encrypted, so keep it safe and unaltered, and remember it also holds everyone else's data on your instance. [ASK YOUR LAWYER: whether, and how, you should keep a backup if investigators ask you to, how long, and what that means for everyone else on your instance.]

### Prevention

- **Do not enroll minors.** Faro v1 is not designed for anyone under 18 ([SELF-HOSTING.md §11](../SELF-HOSTING.md#11-what-you-as-the-operator-can-and-cannot-see)).
- **Give allies this guide** before anything happens, along with the [ally guide](../ALLY-GUIDE.md), and tell them who your safeguarding contact is.

## 7. Where this guidance comes from

The facts about Faro in this guide come from Faro's documentation and source code: [ARCHITECTURE.md](../ARCHITECTURE.md), [PROTOCOL.md](../PROTOCOL.md), the [ally guide](../ALLY-GUIDE.md) and the server code. The reporting routes come from the hotlines' own websites (section 3). Everything else is general guidance. Check it with a lawyer and your safeguarding lead.
