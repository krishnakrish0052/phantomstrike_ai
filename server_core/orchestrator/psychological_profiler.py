"""
server_core/orchestrator/psychological_profiler.py

Psychological Profiling at Scale — OCEAN personality, Dark Triad, cognitive biases
from public online data. Drives personalized social engineering campaigns with
NLP-based personality extraction, cognitive bias detection, and attack-vector
generation tuned to individual psychological vulnerabilities.

Integration points:
  - SocialEngineeringAgent: consumes profiles for targeted phishing generation
  - ReconAgent: feeds discovered people + public data into the profiler
  - HiveMind: publishes PSYCH_PROFILE_COMPLETE events for campaign orchestration
  - EGATSEngine: psychological susceptibility scores weight attack-path nodes
  - AgentMemory: caches profiles per target across a mission session

Research grounding:
  - BIG-5 / OCEAN: Costa & McCrae (1992) — lexically stable across cultures
  - Dark Triad: Paulhus & Williams (2002) — narcissism, Machiavellianism, psychopathy
  - Linguistic markers of personality: Pennebaker & King (1999), Tausczik & Pennebaker (2010)
  - Cognitive biases in phishing: Cialdini's principles of persuasion masquerading as biases
  - Readability / formality: Flesch-Kincaid, Dale-Chall adaptations
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# Constants — lexicons, patterns, scoring tables
# ═══════════════════════════════════════════════════════════════════════════════

# ── Emotion / sentiment lexicons (subset — production would use LIWC or VADER) ──
_POSITIVE_EMOTION_WORDS: Set[str] = {
    "happy", "glad", "excited", "thrilled", "delighted", "pleased", "grateful",
    "wonderful", "fantastic", "excellent", "amazing", "love", "awesome", "great",
    "joy", "cheerful", "optimistic", "proud", "confident", "enthusiastic", "blessed",
    "fortunate", "celebrate", "success", "win", "breakthrough", "achievement",
    "innovative", "brilliant", "outstanding", "exceptional", "superb", "incredible",
}

_NEGATIVE_EMOTION_WORDS: Set[str] = {
    "angry", "furious", "outraged", "annoyed", "frustrated", "irritated", "hostile",
    "sad", "depressed", "miserable", "unhappy", "gloomy", "hopeless", "despair",
    "anxious", "worried", "nervous", "stressed", "fearful", "afraid", "terrified",
    "hate", "disgusted", "resentful", "bitter", "jealous", "envious", "ashamed",
    "guilty", "embarrassed", "lonely", "abandoned", "betrayed", "disappointed",
    "terrible", "horrible", "awful", "dreadful", "pathetic", "useless", "failure",
}

_ANGER_WORDS: Set[str] = {
    "angry", "furious", "outraged", "livid", "irate", "enraged", "infuriated",
    "hostile", "aggressive", "mad", "pissed", "rage", "wrath", "vengeance",
}

_FEAR_WORDS: Set[str] = {
    "afraid", "scared", "frightened", "terrified", "fearful", "panicked",
    "alarmed", "worried", "anxious", "nervous", "dread", "terror", "horror",
}

_SADNESS_WORDS: Set[str] = {
    "sad", "unhappy", "depressed", "gloomy", "miserable", "sorrow", "grief",
    "mourn", "despair", "hopeless", "lonely", "heartbroken", "melancholy",
}

_DISGUST_WORDS: Set[str] = {
    "disgust", "disgusted", "revolting", "repulsive", "gross", "nasty",
    "sickening", "vile", "loathsome", "despise", "detest", "abhor",
}

_SURPRISE_WORDS: Set[str] = {
    "surprised", "shocked", "astonished", "amazed", "stunned", "startled",
    "unexpected", "unbelievable", "incredible", "staggering", "jaw-dropping",
}

# ── Formality markers ──
_FORMAL_MARKERS: Set[str] = {
    "therefore", "thus", "hence", "consequently", "furthermore", "moreover",
    "nevertheless", "nonetheless", "accordingly", "hereby", "herein", "whereas",
    "pursuant", "thereto", "notwithstanding", "heretofore", "whereby",
    "additionally", "subsequently", "specifically", "regarding", "concerning",
}

_INFORMAL_MARKERS: Set[str] = {
    "gonna", "wanna", "gotta", "kinda", "sorta", "dunno", "lemme", "gimme",
    "ain't", "y'all", "yeah", "nah", "nope", "yep", "dude", "cool", "awesome",
    "lol", "haha", "btw", "fyi", "imo", "tbh", "omg", "wtf", "idk", "jk",
    "literally", "basically", "actually", "anyway", "stuff", "thing", "things",
}

# ── Hedging / certainty language ──
_HEDGE_WORDS: Set[str] = {
    "maybe", "perhaps", "possibly", "might", "could", "may", "seems", "appears",
    "likely", "unlikely", "probably", "tends to", "I think", "I believe",
    "I guess", "I suppose", "somewhat", "fairly", "rather", "quite", "sort of",
    "kind of", "a bit", "a little", "tend to", "inclined to", "arguably",
}

_CERTAINTY_WORDS: Set[str] = {
    "certainly", "definitely", "undoubtedly", "absolutely", "always", "never",
    "clearly", "obviously", "surely", "indeed", "without doubt", "guaranteed",
    "must", "will", "shall", "proven", "confirmed", "undeniable", "unequivocal",
}

# ── Self-reference / narcissism indicators ──
_SELF_REFERENCE_PATTERNS: List[str] = [
    r"\bI\b", r"\bme\b", r"\bmy\b", r"\bmine\b", r"\bmyself\b",
    r"\bI've\b", r"\bI'm\b", r"\bI'll\b", r"\bI'd\b",
]

# ── Cognitive bias keywords / indicators ──
_BIAS_INDICATORS: Dict[str, Dict[str, Any]] = {
    "authority_bias": {
        "keywords": [
            "expert", "authority", "official", "certified", "endorsed",
            "approved", "recommended by", "leading", "top", "senior",
            "chief", "director", "vp", "phd", "doctor", "professor",
            "credentials", "accredited", "licensed",
        ],
        "role_weights": {"Executive": 0.9, "Manager": 0.7, "Junior": 0.5},
        "description": "Deference to authority figures, titles, credentials",
    },
    "urgency_bias": {
        "keywords": [
            "urgent", "immediately", "asap", "right away", "deadline",
            "critical", "emergency", "time-sensitive", "last chance",
            "limited time", "expires", "now", "today only", "hurry",
            "act fast", "don't wait", "before it's too late", "closing",
        ],
        "temporal_cues": "Responds to time pressure in communications",
        "description": "Susceptibility to time-pressure decision manipulation",
    },
    "curiosity_bias": {
        "keywords": [
            "secret", "exclusive", "leaked", "confidential", "insider",
            "behind the scenes", "you won't believe", "what they don't want you to know",
            "revealed", "exposed", "hidden", "discover", "uncover",
        ],
        "role_weights": {"Developer": 0.85, "Researcher": 0.9, "Engineer": 0.8},
        "description": "Compulsion to click curiosity-gap content",
    },
    "reciprocity_bias": {
        "keywords": [
            "favor", "help", "assist", "support", "give back", "return",
            "in exchange", "mutual", "share", "collaborate", "I did X for you",
            "you owe", "pay it forward", "returning the favor",
        ],
        "description": "Feeling obligated to reciprocate even unsolicited gestures",
    },
    "confirmation_bias": {
        "keywords": [
            "as you know", "you already believe", "consistent with", "proves",
            "confirms", "validates", "supports", "evidence that", "agrees with",
            "reinforces", "backs up", "aligns with your view",
        ],
        "description": "Seeking/accepting only information that confirms existing beliefs",
    },
    "social_proof": {
        "keywords": [
            "everyone is", "join thousands", "most popular", "best-selling",
            "top-rated", "trending", "viral", "community", "others are",
            "your colleagues", "your peers", "X people have", "recommended by others",
            "trusted by", "millions of", "widely used",
        ],
        "description": "Conforming because others are doing it",
    },
    "scarcity_bias": {
        "keywords": [
            "limited", "exclusive", "rare", "only a few", "while supplies last",
            "sold out soon", "scarce", "in demand", "high demand", "waiting list",
            "first come", "one-time", "never again", "closing soon", "few remaining",
        ],
        "description": "Placing higher value on scarce/limited opportunities",
    },
    "liking_bias": {
        "keywords": [
            "friend", "friendly", "like you", "similar", "in common",
            "shared interest", "connection", "rapport", "bond", "trust",
            "we're alike", "same as me", "kindred", "soulmate", "compatible",
        ],
        "description": "More easily influenced by people we like or find similar",
    },
}

# ── Big Five behavioural signals from online data ──
# Each trait maps observable behaviours → score adjustment (positive or negative)
_BIG_FIVE_SIGNALS: Dict[str, Dict[str, Dict[str, float]]] = {
    "openness": {
        "diverse_interests": {"signal": "profile has 5+ distinct topics", "weight": 0.15},
        "creative_language": {"signal": "uses metaphors, vivid imagery", "weight": 0.10},
        "intellectual_curiosity": {"signal": "follows diverse thought leaders", "weight": 0.12},
        "adventurous": {"signal": "mentions travel, new experiences", "weight": 0.10},
        "libertarian_values": {"signal": "mentions freedom, independence", "weight": 0.08},
        "conventional_language": {"signal": "uses cliches, safe language", "weight": -0.10},
        "routine_focused": {"signal": "mentions routine, stability, tradition", "weight": -0.12},
    },
    "conscientiousness": {
        "achievement_language": {"signal": "uses accomplishment words", "weight": 0.12},
        "detail_oriented": {"signal": "long posts, structured arguments", "weight": 0.10},
        "punctuality_words": {"signal": "mentions deadlines, schedules", "weight": 0.10},
        "orderly_language": {"signal": "numbered lists, structured writing", "weight": 0.08},
        "impulsive_language": {"signal": "exclamation-heavy, short messages", "weight": -0.12},
        "disorganized_writing": {"signal": "fragmented, typos, inconsistency", "weight": -0.10},
    },
    "extraversion": {
        "social_language": {"signal": "many social references, 'we', 'us'", "weight": 0.15},
        "high_activity": {"signal": "frequent posts, many interactions", "weight": 0.12},
        "assertive_language": {"signal": "declarative statements, certainty", "weight": 0.10},
        "enthusiasm_words": {"signal": "exclamation marks, excitement words", "weight": 0.08},
        "introvert_markers": {"signal": "few posts, private accounts", "weight": -0.12},
        "low_social_reference": {"signal": "mostly 'I', rarely 'we'", "weight": -0.08},
    },
    "agreeableness": {
        "polite_language": {"signal": "uses please, thanks, respectful tone", "weight": 0.12},
        "empathy_words": {"signal": "uses feeling words for others", "weight": 0.12},
        "cooperative": {"signal": "collaborative language, 'we solved'", "weight": 0.10},
        "conflict_avoidant": {"signal": "hedging, softening disagreements", "weight": 0.08},
        "hostile_language": {"signal": "insults, aggression, combativeness", "weight": -0.15},
        "competitive_language": {"signal": "win/lose framing, zero-sum", "weight": -0.10},
    },
    "neuroticism": {
        "negative_emotion": {"signal": "high negative emotion word count", "weight": 0.15},
        "anxiety_words": {"signal": "worry, stress, anxiety terms", "weight": 0.12},
        "self_deprecation": {"signal": "negative self-talk, insecurity", "weight": 0.10},
        "emotional_volatility": {"signal": "mood swings across posts", "weight": 0.10},
        "stability_markers": {"signal": "even tone, resilience language", "weight": -0.12},
        "confident_language": {"signal": "high certainty, low hedging", "weight": -0.10},
    },
}

# ── Dark Triad language indicators ──
_DARK_TRIAD_INDICATORS: Dict[str, Dict[str, Any]] = {
    "narcissism": {
        "keywords": [
            "I", "me", "my", "mine", "myself", "I'm", "I've",
            "best", "greatest", "brilliant", "genius", "elite", "superior",
            "dominate", "crush", "destroy", "win", "winner", "champion",
            "look at me", "check me out", "my achievement", "I built",
            "I created", "I led", "my team", "under my", "thanks to me",
        ],
        "signal": "excessive self-reference, grandiosity, entitlement language",
        "weight_first_person_ratio": 0.3,
    },
    "machiavellianism": {
        "keywords": [
            "strategy", "tactical", "leverage", "influence", "manipulate",
            "control", "power", "advantage", "exploit", "play", "game",
            "chess", "move", "positioning", "alliance", "useful", "resource",
            "end justifies", "whatever it takes", "by any means",
            "ends", "means to an end", "pragmatic", "realpolitik",
        ],
        "signal": "instrumental view of relationships, strategic cynicism",
        "weight_power_language": 0.25,
    },
    "psychopathy": {
        "keywords": [
            "don't care", "whatever", "bored", "thrill", "risk", "dangerous",
            "reckless", "impulsive", "wild", "crazy", "insane", "dare",
            "no remorse", "their fault", "they deserved", "no sympathy",
            "cold", "heartless", "ruthless", "merciless", "savage",
        ],
        "signal": "callousness, lack of empathy, impulsivity, sensation-seeking",
        "weight_empathy_deficit": 0.3,
    },
}

# ── Attack vector catalog mapped to psychological vulnerabilities ──
_ATTACK_VECTORS: Dict[str, Dict[str, Any]] = {
    "authority_impersonation": {
        "exploits": ["authority_bias", "social_proof"],
        "traits": {"agreeableness": "high", "openness": "low"},
        "personas": ["IT Support", "CEO", "Government Official", "Auditor", "Legal Counsel"],
        "effectiveness": 0.75,
        "description": "Impersonating authority figures to compel compliance",
    },
    "urgency_drive_by": {
        "exploits": ["urgency_bias", "scarcity_bias"],
        "traits": {"neuroticism": "high", "conscientiousness": "high"},
        "personas": ["Security Team", "Helpdesk", "Bank", "Delivery Service"],
        "effectiveness": 0.82,
        "description": "Time-pressure tactics forcing action before reflection",
    },
    "curiosity_gap": {
        "exploits": ["curiosity_bias"],
        "traits": {"openness": "high", "neuroticism": "any"},
        "personas": ["Anonymous Leaker", "Whistleblower", "Recruiter", "Journalist"],
        "effectiveness": 0.70,
        "description": "Clickbait and information-gap lures",
    },
    "reciprocity_trap": {
        "exploits": ["reciprocity_bias", "liking_bias"],
        "traits": {"agreeableness": "high"},
        "personas": ["Friendly Colleague", "Mentor", "Peer", "Industry Contact"],
        "effectiveness": 0.68,
        "description": "Offering unsolicited value to create obligation",
    },
    "social_proof_cascade": {
        "exploits": ["social_proof", "confirmation_bias"],
        "traits": {"extraversion": "high", "openness": "high"},
        "personas": ["Industry Influencer", "Peer Group", "Community Leader"],
        "effectiveness": 0.73,
        "description": "Leveraging herd behaviour and consensus illusions",
    },
    "liking_and_similarity": {
        "exploits": ["liking_bias", "reciprocity_bias"],
        "traits": {"agreeableness": "high", "extraversion": "high"},
        "personas": ["Shared Interest Group", "Alumni", "Conference Buddy", "Hobby Peer"],
        "effectiveness": 0.71,
        "description": "Building false rapport through manufactured similarity",
    },
    "fear_and_intimidation": {
        "exploits": ["authority_bias", "urgency_bias"],
        "traits": {"neuroticism": "high", "agreeableness": "high"},
        "personas": ["Law Enforcement", "Regulator", "IRS/Tax Authority", "Security Auditor"],
        "effectiveness": 0.78,
        "description": "Fear-based compliance demands (spear-phishing)",
    },
    "ego_stroking": {
        "exploits": ["confirmation_bias", "liking_bias"],
        "dark_triad": {"narcissism": "high"},
        "personas": ["Recruiter", "Award Committee", "Conference Organizer", "Journalist"],
        "effectiveness": 0.85,
        "description": "Flattery and recognition bait targeting narcissistic traits",
    },
    "guilt_and_duty": {
        "exploits": ["reciprocity_bias", "authority_bias"],
        "traits": {"conscientiousness": "high", "agreeableness": "high"},
        "personas": ["Manager", "Team Lead", "Direct Report", "Client"],
        "effectiveness": 0.69,
        "description": "Obligation and responsibility exploitation",
    },
}

# ── Phishing template fragments ──
_PHISH_OPENINGS: Dict[str, List[str]] = {
    "authority_impersonation": [
        "This is {persona} from {org}. An official security audit has flagged your account.",
        "Per directive from {persona}, all {org} personnel must complete the following verification.",
        "{persona} has requested an immediate review of your access credentials.",
    ],
    "urgency_drive_by": [
        "URGENT: Your {service} access will be suspended in {time_window}.",
        "ACTION REQUIRED within {time_window}: Verify your {service} account.",
        "CRITICAL: Unauthorized access detected. Immediate response required.",
    ],
    "curiosity_gap": [
        "I wasn't supposed to share this, but you should see what I found about {org}.",
        "Confidential: The {org} {document_type} everyone is talking about.",
        "You're mentioned in this leaked document. I thought you should know.",
    ],
    "reciprocity_trap": [
        "I noticed your work on {topic} — really impressive. I've put together some resources you might find useful.",
        "Thanks for your contribution to {topic}. I wanted to share something in return.",
        "Your post about {topic} helped me. Here's something that helped me — thought you'd appreciate it.",
    ],
    "social_proof_cascade": [
        "{count} of your colleagues at {org} have already signed up for {service}.",
        "Join {count}+ professionals from {org} who are using {service}.",
        "Your team at {org} is already on {service} — don't get left behind.",
    ],
    "liking_and_similarity": [
        "Hey {name}, I'm also a {shared_interest} enthusiast. Have you seen this?",
        "Fellow {shared_interest} person here — thought you'd appreciate this {resource}.",
        "I think we met at {event}. Great conversation about {topic} — here's that link I mentioned.",
    ],
    "fear_and_intimidation": [
        "NOTICE OF NON-COMPLIANCE: {org} has been flagged for regulatory review.",
        "OFFICIAL INQUIRY: Your {org} account is under investigation.",
        "LEGAL NOTICE: Failure to respond may result in account termination.",
    ],
    "ego_stroking": [
        "Your expertise in {topic} has been noticed. We'd like to feature you in {publication}.",
        "Congratulations {name}! You've been nominated for {award}.",
        "Your work at {org} is exceptional. We'd like to discuss an exclusive opportunity.",
    ],
    "guilt_and_duty": [
        "{name}, the team is waiting on your input for the {project} deliverable.",
        "We're falling behind on {project} and really need your section by {deadline}.",
        "The client is asking for an update. Can you review this and get back ASAP?",
    ],
}

_PHISH_CLOSERS: Dict[str, List[str]] = {
    "authority_impersonation": [
        "This is a mandatory security procedure. Non-compliance will be reported.",
        "Please complete this verification within 24 hours to maintain your access.",
        "Reply directly to this email with confirmation of receipt.",
    ],
    "urgency_drive_by": [
        "This link expires in {time_window}. Act now to avoid service interruption.",
        "Click below to verify — the window closes {deadline}.",
        "Immediate action required. This notification will self-destruct.",
    ],
    "curiosity_gap": [
        "I'll leave this up for 24 hours. Don't share it widely.",
        "Let me know what you think. This is sensitive, so please be discreet.",
        "I trust you'll handle this information appropriately.",
    ],
    "reciprocity_trap": [
        "No pressure — just thought you'd find it useful. Let me know what you think!",
        "Hope these help! Would love to hear your thoughts when you have a moment.",
        "Happy to share more if you're interested. Let me know!",
    ],
    "social_proof_cascade": [
        "Join your colleagues who are already benefiting from {service}.",
        "Don't miss out — the {org} community is already here.",
        "See what everyone at {org} is talking about.",
    ],
    "liking_and_similarity": [
        "Would love to connect more about {shared_interest}!",
        "Let me know if you want to grab a virtual coffee and chat {shared_interest}.",
        "Hope to see you at the next {shared_interest} meetup!",
    ],
    "fear_and_intimidation": [
        "This matter requires your immediate attention. Forward to legal if needed.",
        "Failure to comply may result in escalation. You have 48 hours.",
        "We urge you to take this seriously. Your cooperation is required.",
    ],
    "ego_stroking": [
        "We'd be honored to have you involved. Let us know your availability.",
        "This is an exclusive opportunity. We hope you'll consider it.",
        "Your reputation precedes you. We're excited about the possibility.",
    ],
    "guilt_and_duty": [
        "Thanks for taking care of this — the team is counting on you.",
        "Really appreciate you handling this. Let me know if you hit any blockers.",
        "Your contribution is critical. Thanks for prioritizing this.",
    ],
}

# ── Readability reference tables ──
# Dale-Chall easy word list (extract — production would have the full 3000-word list)
_DALE_CHALL_EASY: Set[str] = {
    "a", "able", "about", "above", "act", "add", "afraid", "after", "again",
    "against", "age", "ago", "agree", "air", "all", "allow", "also", "always",
    "am", "among", "an", "and", "anger", "angry", "animal", "another", "answer",
    "any", "appear", "apple", "are", "arm", "ask", "at", "away",
    "baby", "back", "bad", "bag", "ball", "band", "bank", "base", "be",
    "bear", "beat", "beauty", "became", "because", "become", "bed", "been",
    "before", "begin", "behind", "being", "believe", "bell", "belong", "below",
    "beside", "best", "better", "between", "big", "bird", "bit", "black",
    "block", "blood", "blow", "blue", "board", "boat", "body", "book", "born",
    "both", "bottom", "box", "boy", "break", "bright", "bring", "broad",
    "broke", "brother", "brown", "build", "burn", "bus", "business", "but",
    "buy", "by",
    "call", "came", "can", "capital", "car", "care", "carry", "case", "cat",
    "catch", "cause", "center", "century", "certain", "chair", "chance",
    "change", "check", "child", "children", "church", "circle", "city", "class",
    "clean", "clear", "close", "coast", "cold", "college", "color", "come",
    "common", "company", "condition", "contain", "continue", "control", "cook",
    "cool", "copy", "corner", "cost", "could", "count", "country", "course",
    "court", "cover", "cross", "crowd", "cry", "cut",
    "dance", "dark", "day", "dead", "deal", "dear", "death", "decide",
    "deep", "department", "describe", "desk", "did", "die", "different",
    "direct", "discover", "do", "doctor", "does", "dog", "done", "door",
    "double", "down", "draw", "dream", "dress", "drink", "drive", "drop",
    "dry", "during",
    "each", "ear", "early", "earth", "east", "easy", "eat", "edge", "egg",
    "eight", "either", "else", "empty", "end", "enemy", "enjoy", "enough",
    "enter", "even", "evening", "event", "ever", "every", "example", "except",
    "expect", "explain", "eye",
    "face", "fact", "fair", "fall", "family", "far", "farm", "fast", "father",
    "fear", "feel", "feet", "fell", "few", "field", "fight", "figure", "fill",
    "final", "find", "fine", "finger", "finish", "fire", "first", "fish",
    "five", "flat", "floor", "flow", "flower", "fly", "follow", "food",
    "foot", "for", "force", "foreign", "forest", "form", "found", "four",
    "free", "fresh", "friend", "from", "front", "full", "fun", "future",
    "game", "garden", "gas", "gave", "general", "get", "girl", "give",
    "glad", "glass", "go", "god", "gold", "gone", "good", "got",
    "govern", "great", "green", "ground", "group", "grow", "gun",
    "had", "hair", "half", "hand", "happen", "happy", "hard", "has",
    "hat", "have", "he", "head", "hear", "heart", "heat", "heavy",
    "held", "help", "her", "here", "high", "hill", "him", "his",
    "history", "hit", "hold", "hole", "home", "hope", "horse", "hospital",
    "hot", "hour", "house", "how", "human", "hundred", "hunt", "hurry",
    "I", "ice", "idea", "if", "important", "in", "inch", "include",
    "increase", "inside", "into", "iron", "is", "island", "it",
    "job", "join", "joy", "just",
    "keep", "kept", "key", "kill", "kind", "king", "kitchen", "knew",
    "know",
    "labor", "lake", "land", "language", "large", "last", "late", "laugh",
    "law", "lay", "lead", "learn", "leave", "led", "left", "leg", "less",
    "let", "letter", "life", "light", "like", "line", "list", "listen",
    "little", "live", "long", "look", "lost", "lot", "loud", "love",
    "low",
    "machine", "made", "main", "make", "man", "many", "map", "mark",
    "master", "matter", "may", "me", "mean", "measure", "meet", "men",
    "middle", "might", "mile", "milk", "million", "mind", "minute", "miss",
    "modern", "moment", "money", "month", "moon", "more", "morning", "most",
    "mother", "mountain", "move", "much", "music", "must", "my",
    "name", "nation", "near", "need", "never", "new", "next", "night",
    "nine", "no", "north", "nose", "not", "note", "nothing", "notice",
    "now", "number",
    "ocean", "of", "off", "offer", "office", "often", "oh", "oil", "old",
    "on", "once", "one", "only", "open", "or", "order", "other", "our",
    "out", "over", "own",
    "page", "paint", "pair", "paper", "part", "party", "pass", "past",
    "pay", "people", "perhaps", "period", "person", "pick", "picture",
    "piece", "place", "plan", "plant", "play", "please", "point", "police",
    "poor", "popular", "port", "position", "possible", "post", "power",
    "prepare", "present", "press", "pretty", "price", "private", "problem",
    "produce", "product", "program", "provide", "public", "pull", "push",
    "put",
    "question", "quick", "quiet", "quite",
    "race", "radio", "rain", "raise", "ran", "rather", "reach", "read",
    "ready", "real", "reason", "receive", "record", "red", "remain",
    "remember", "report", "rest", "result", "return", "rich", "ride",
    "right", "ring", "rise", "river", "road", "rock", "roll", "room",
    "round", "row", "rule", "run",
    "sad", "safe", "said", "same", "sat", "save", "saw", "say", "school",
    "sea", "season", "seat", "second", "see", "seem", "self", "sell",
    "send", "sense", "sent", "serve", "set", "seven", "several", "shall",
    "shape", "share", "sharp", "she", "ship", "shoe", "shop", "short",
    "should", "show", "side", "sight", "sign", "silver", "simple", "since",
    "sing", "sister", "sit", "six", "size", "skill", "skin", "sky",
    "sleep", "small", "smile", "snow", "so", "soft", "soil", "soldier",
    "some", "son", "song", "soon", "sound", "south", "space", "speak",
    "special", "speed", "spend", "spirit", "sport", "spread", "spring",
    "square", "stand", "star", "start", "state", "station", "stay", "step",
    "still", "stone", "stood", "stop", "store", "story", "street",
    "strong", "student", "study", "such", "sudden", "sugar", "summer",
    "sun", "supply", "support", "sure", "surprise", "sweet", "system",
    "table", "take", "talk", "tall", "teach", "team", "teeth", "tell",
    "ten", "test", "than", "that", "the", "their", "them", "then",
    "there", "these", "they", "thing", "think", "this", "those",
    "though", "thousand", "three", "through", "tie", "time", "tire",
    "to", "today", "together", "told", "tomorrow", "tonight", "too",
    "took", "top", "touch", "toward", "town", "train", "travel",
    "tree", "trouble", "true", "try", "turn", "two",
    "under", "understand", "unit", "until", "up", "upon", "us", "use",
    "usual",
    "valley", "value", "very", "view", "village", "visit", "voice",
    "wait", "walk", "wall", "want", "war", "warm", "was", "wash",
    "watch", "water", "wave", "way", "we", "wear", "weather", "week",
    "weight", "well", "went", "were", "west", "what", "wheel", "when",
    "where", "which", "while", "white", "who", "why", "wide", "wife",
    "wild", "will", "win", "wind", "window", "winter", "wire", "wise",
    "wish", "with", "woman", "women", "wood", "word", "work", "world",
    "would", "write", "wrong", "wrote",
    "year", "yellow", "yes", "yesterday", "yet", "you", "young",
}

# ═══════════════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class WritingStyleProfile:
    """Linguistic fingerprint extracted from a corpus of a person's writing."""

    # ── Core metrics ──
    formality_score: float = 0.5  # 0.0 (casual) → 1.0 (formal)
    emotional_tone: Dict[str, float] = field(default_factory=dict)  # positive, negative, anger, fear, sadness, disgust, surprise
    complexity_score: float = 0.5  # 0.0 → 1.0 based on readability + sentence structure
    vocabulary_level: float = 0.5  # 0.0 → 1.0 based on word rarity / sophistication

    # ── Detailed metrics ──
    avg_sentence_length: float = 0.0
    avg_word_length: float = 0.0
    type_token_ratio: float = 0.0  # unique words / total words (lexical diversity)
    flesch_reading_ease: float = 50.0
    flesch_kincaid_grade: float = 10.0
    dale_chall_score: float = 5.0

    # ── Linguistic features ──
    hedge_ratio: float = 0.0  # hedging words / total words
    certainty_ratio: float = 0.0  # certainty words / total words
    self_reference_ratio: float = 0.0  # first-person pronouns / total words
    social_reference_ratio: float = 0.0  # we/us/our / total words
    question_frequency: float = 0.0  # questions per sentence
    exclamation_frequency: float = 0.0  # ! per sentence
    punctuation_formality: float = 0.5  # semicolons, colons, em-dashes → formal

    # ── Source data ──
    total_words: int = 0
    total_sentences: int = 0
    source_count: int = 0  # number of text samples analyzed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "formality_score": self.formality_score,
            "emotional_tone": self.emotional_tone,
            "complexity_score": self.complexity_score,
            "vocabulary_level": self.vocabulary_level,
            "avg_sentence_length": self.avg_sentence_length,
            "avg_word_length": self.avg_word_length,
            "type_token_ratio": self.type_token_ratio,
            "flesch_reading_ease": self.flesch_reading_ease,
            "flesch_kincaid_grade": self.flesch_kincaid_grade,
            "dale_chall_score": self.dale_chall_score,
            "hedge_ratio": self.hedge_ratio,
            "certainty_ratio": self.certainty_ratio,
            "self_reference_ratio": self.self_reference_ratio,
            "social_reference_ratio": self.social_reference_ratio,
            "question_frequency": self.question_frequency,
            "exclamation_frequency": self.exclamation_frequency,
            "punctuation_formality": self.punctuation_formality,
            "total_words": self.total_words,
            "total_sentences": self.total_sentences,
            "source_count": self.source_count,
        }


@dataclass
class PersonalityProfile:
    """Estimated OCEAN + Dark Triad traits with confidence intervals."""

    name: str = ""
    org: str = ""
    roles: List[str] = field(default_factory=list)

    # Big Five (each 0.0 → 1.0, normalized around 0.5 as population mean)
    openness: float = 0.5
    conscientiousness: float = 0.5
    extraversion: float = 0.5
    agreeableness: float = 0.5
    neuroticism: float = 0.5

    # Dark Triad (each 0.0 → 1.0)
    narcissism: float = 0.2
    machiavellianism: float = 0.2
    psychopathy: float = 0.1

    # Confidence
    confidence: float = 0.5  # overall confidence in profile accuracy (0.0 → 1.0)
    evidence_count: int = 0  # number of behavioural signals observed

    # Bias susceptibility (0.0 → 1.0 each)
    biases: Dict[str, float] = field(default_factory=dict)

    # Source data
    sources: List[str] = field(default_factory=list)
    analyzed_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "org": self.org,
            "roles": self.roles,
            "big_five": {
                "openness": self.openness,
                "conscientiousness": self.conscientiousness,
                "extraversion": self.extraversion,
                "agreeableness": self.agreeableness,
                "neuroticism": self.neuroticism,
            },
            "dark_triad": {
                "narcissism": self.narcissism,
                "machiavellianism": self.machiavellianism,
                "psychopathy": self.psychopathy,
            },
            "confidence": self.confidence,
            "evidence_count": self.evidence_count,
            "biases": self.biases,
            "sources": self.sources,
            "analyzed_at": self.analyzed_at,
        }


@dataclass
class VulnerabilityMap:
    """A ranked list of people by psychological exploitability."""

    org_name: str = ""
    generated_at: str = ""
    rankings: List[Dict[str, Any]] = field(default_factory=list)
    weakest_link: Optional[Dict[str, Any]] = None
    average_susceptibility: float = 0.0
    high_risk_count: int = 0  # people with susceptibility > 0.7


# ═══════════════════════════════════════════════════════════════════════════════
# PsychologicalProfiler
# ═══════════════════════════════════════════════════════════════════════════════


class PsychologicalProfiler:
    """Builds complete psychological profiles from public online data.

    Integrates writing-style NLP analysis, behavioural-to-trait mapping, cognitive
    bias detection, and personalized attack-vector generation. Designed to feed
    the SocialEngineeringAgent with high-fidelity target profiles for authorized
    security testing.

    Usage::

        profiler = PsychologicalProfiler()
        profile = profiler.profile_person("Jane Doe", "Acme Corp",
                                          sources=["twitter", "linkedin", "blog"])
        phish = profiler.generate_personalized_phish(profile, "password_reset")
    """

    BIG_FIVE = ["openness", "conscientiousness", "extraversion", "agreeableness", "neuroticism"]
    DARK_TRIAD = ["narcissism", "machiavellianism", "psychopathy"]
    COGNITIVE_BIASES = [
        "authority_bias", "urgency_bias", "curiosity_bias", "reciprocity_bias",
        "confirmation_bias", "social_proof", "scarcity_bias", "liking_bias",
    ]

    def __init__(self):
        self._profiles: Dict[str, PersonalityProfile] = {}
        self._writing_cache: Dict[str, WritingStyleProfile] = {}
        self._org_profiles: Dict[str, Dict[str, Any]] = {}

    # ──────────────────────────────────────────────────────────────────────
    # profile_person
    # ──────────────────────────────────────────────────────────────────────

    def profile_person(
        self, name: str, org: str, sources: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Build complete psychological profile from available public sources.

        Aggregates data from LinkedIn, Twitter, GitHub, personal blogs, conference
        talks, and other public data to construct a multi-dimensional psychological
        profile including OCEAN traits, Dark Triad levels, cognitive bias
        susceptibility, and recommended attack vectors.

        Args:
            name: Target person's full name.
            org: Organization they belong to (context for role, culture, etc.).
            sources: List of source types to simulate (twitter, linkedin, github,
                     blog, talks, papers, reddit, stackoverflow, etc.).

        Returns:
            Complete profile dict suitable for SocialEngineeringAgent consumption.
        """
        sources = sources or ["linkedin", "twitter", "github", "blog"]
        profile_key = f"{name}:{org}"

        if profile_key in self._profiles:
            logger.info("Returning cached profile for %s", profile_key)
            return self._profiles[profile_key].to_dict()

        logger.info("Building psychological profile for %s @ %s (sources: %s)",
                     name, org, sources)

        # ── Phase 1: Gather simulated profile data from each source ──
        profile_data = self._aggregate_source_data(name, org, sources)

        # ── Phase 2: Analyze writing style from text samples ──
        writing_style = self.analyze_writing_style(profile_data.get("texts", []))

        # ── Phase 3: Extract personality traits ──
        traits = self.extract_personality_traits(profile_data)

        # ── Phase 4: Find cognitive biases ──
        biases = self.find_cognitive_biases(profile_data)

        # ── Phase 5: Assemble profile ──
        profile = PersonalityProfile(
            name=name,
            org=org,
            roles=profile_data.get("roles", []),
            openness=traits.get("openness", 0.5),
            conscientiousness=traits.get("conscientiousness", 0.5),
            extraversion=traits.get("extraversion", 0.5),
            agreeableness=traits.get("agreeableness", 0.5),
            neuroticism=traits.get("neuroticism", 0.5),
            narcissism=traits.get("narcissism", 0.2),
            machiavellianism=traits.get("machiavellianism", 0.2),
            psychopathy=traits.get("psychopathy", 0.1),
            confidence=traits.get("_confidence", 0.5),
            evidence_count=traits.get("_evidence_count", 0),
            biases=biases,
            sources=sources,
            analyzed_at=datetime.now(timezone.utc).isoformat(),
        )

        self._profiles[profile_key] = profile
        logger.info("Profile complete for %s: O=%.2f C=%.2f E=%.2f A=%.2f N=%.2f (confidence=%.2f)",
                     name, profile.openness, profile.conscientiousness,
                     profile.extraversion, profile.agreeableness, profile.neuroticism,
                     profile.confidence)

        return profile.to_dict()

    # ──────────────────────────────────────────────────────────────────────
    # analyze_writing_style
    # ──────────────────────────────────────────────────────────────────────

    def analyze_writing_style(self, texts: List[str]) -> Dict[str, Any]:
        """NLP analysis: formality, emotional tone, complexity, vocabulary level.

        Performs multi-dimensional linguistic analysis on a corpus of text samples.
        Computes readability (Flesch-Kincaid, Dale-Chall), emotional tone via
        lexicon matching, formality via register markers, and vocabulary
        sophistication via type-token ratio and rare-word density.

        Args:
            texts: List of text samples attributed to the target.

        Returns:
            WritingStyleProfile serialized to dict.
        """
        if not texts:
            logger.debug("No texts provided for writing style analysis")
            return WritingStyleProfile().to_dict()

        # ── Flatten and clean ──
        clean_texts = []
        for t in texts:
            if t and isinstance(t, str) and len(t.strip()) > 20:
                clean_texts.append(t.strip())

        if not clean_texts:
            return WritingStyleProfile().to_dict()

        combined = " ".join(clean_texts)

        # ── Tokenize ──
        words = self._tokenize(combined)
        sentences = self._split_sentences(combined)
        total_words = len(words)
        total_sentences = len(sentences) or 1

        if total_words < 10:
            return WritingStyleProfile(
                total_words=total_words,
                total_sentences=total_sentences,
                source_count=len(clean_texts),
            ).to_dict()

        # ── Basic metrics ──
        avg_sentence_length = total_words / total_sentences
        avg_word_length = sum(len(w) for w in words) / total_words

        # ── Lexical diversity: Type-Token Ratio (TTR) ──
        unique_words = set(w.lower() for w in words)
        type_token_ratio = len(unique_words) / total_words

        # ── Readability: Flesch-Kincaid ──
        syllable_count = self._count_syllables(words)
        flesch_ease = 206.835 - 1.015 * (total_words / total_sentences) - 84.6 * (syllable_count / total_words)
        flesch_ease = max(0.0, min(120.0, flesch_ease))
        flesch_grade = 0.39 * (total_words / total_sentences) + 11.8 * (syllable_count / total_words) - 15.59
        flesch_grade = max(0.0, min(20.0, flesch_grade))

        # ── Readability: Dale-Chall ──
        dale_chall = self._dale_chall_score(words, total_sentences)

        # ── Formality score ──
        formal_count = sum(1 for w in words if w.lower() in _FORMAL_MARKERS)
        informal_count = sum(1 for w in words if w.lower() in _INFORMAL_MARKERS)
        formality_raw = (formal_count - informal_count) / total_words
        formality_score = self._sigmoid(formality_raw * 50 + 0.5)  # normalize to 0–1

        # ── Punctuation formality ──
        semicolons = combined.count(";")
        em_dashes = combined.count("—") + combined.count("--")
        exclamations = combined.count("!")
        punct_formality = (semicolons + em_dashes) / max(semicolons + em_dashes + exclamations, 1)
        if semicolons + em_dashes + exclamations == 0:
            punct_formality = 0.5

        # ── Emotional tone ──
        words_lower = [w.lower() for w in words]
        emotional_tone = {
            "positive": sum(1 for w in words_lower if w in _POSITIVE_EMOTION_WORDS) / total_words,
            "negative": sum(1 for w in words_lower if w in _NEGATIVE_EMOTION_WORDS) / total_words,
            "anger": sum(1 for w in words_lower if w in _ANGER_WORDS) / total_words,
            "fear": sum(1 for w in words_lower if w in _FEAR_WORDS) / total_words,
            "sadness": sum(1 for w in words_lower if w in _SADNESS_WORDS) / total_words,
            "disgust": sum(1 for w in words_lower if w in _DISGUST_WORDS) / total_words,
            "surprise": sum(1 for w in words_lower if w in _SURPRISE_WORDS) / total_words,
        }
        # Normalize emotional tone
        total_emo = sum(emotional_tone.values())
        if total_emo > 0:
            emotional_tone = {k: v / total_emo for k, v in emotional_tone.items()}

        # ── Hedge / certainty ratios ──
        hedge_ratio = sum(1 for w in words_lower if w in _HEDGE_WORDS) / total_words
        certainty_ratio = sum(1 for w in words_lower if w in _CERTAINTY_WORDS) / total_words

        # ── Self-reference / social-reference ratios ──
        self_ref_count = 0
        for pattern in _SELF_REFERENCE_PATTERNS:
            self_ref_count += len(re.findall(pattern, combined))
        self_reference_ratio = self_ref_count / total_words

        social_words = ["we", "us", "our", "ours", "ourselves", "we've", "we're", "we'll"]
        social_ref_count = sum(1 for w in words_lower if w in social_words)
        social_reference_ratio = social_ref_count / total_words

        # ── Question / exclamation frequency ──
        question_frequency = combined.count("?") / total_sentences
        exclamation_frequency = exclamations / total_sentences

        # ── Complexity score (inverse of readability) ──
        # Flesch ease: high = easy; low = complex. Invert and normalize.
        complexity_score = 1.0 - (flesch_ease / 100.0)
        complexity_score = max(0.0, min(1.0, complexity_score))

        # ── Vocabulary level (based on word length, TTR, and Dale-Chall) ──
        vocab_from_length = min(1.0, avg_word_length / 7.0)
        vocab_from_ttr = min(1.0, type_token_ratio / 0.8)
        vocab_from_dc = min(1.0, dale_chall / 10.0)
        vocabulary_level = (vocab_from_length * 0.3 + vocab_from_ttr * 0.3 + vocab_from_dc * 0.4)

        profile = WritingStyleProfile(
            formality_score=round(formality_score, 4),
            emotional_tone={k: round(v, 4) for k, v in emotional_tone.items()},
            complexity_score=round(complexity_score, 4),
            vocabulary_level=round(vocabulary_level, 4),
            avg_sentence_length=round(avg_sentence_length, 2),
            avg_word_length=round(avg_word_length, 2),
            type_token_ratio=round(type_token_ratio, 4),
            flesch_reading_ease=round(flesch_ease, 2),
            flesch_kincaid_grade=round(flesch_grade, 2),
            dale_chall_score=round(dale_chall, 2),
            hedge_ratio=round(hedge_ratio, 4),
            certainty_ratio=round(certainty_ratio, 4),
            self_reference_ratio=round(self_reference_ratio, 4),
            social_reference_ratio=round(social_reference_ratio, 4),
            question_frequency=round(question_frequency, 4),
            exclamation_frequency=round(exclamation_frequency, 4),
            punctuation_formality=round(punct_formality, 4),
            total_words=total_words,
            total_sentences=total_sentences,
            source_count=len(clean_texts),
        )

        # Cache writing profile for reuse
        cache_key = hashlib.md5(combined.encode()).hexdigest()
        self._writing_cache[cache_key] = profile

        logger.debug(
            "Writing style: formality=%.2f complexity=%.2f vocab=%.2f "
            "positive=%.3f negative=%.3f self-ref=%.3f (n=%d words, %d sents)",
            formality_score, complexity_score, vocabulary_level,
            emotional_tone.get("positive", 0), emotional_tone.get("negative", 0),
            self_reference_ratio, total_words, total_sentences,
        )

        return profile.to_dict()

    # ──────────────────────────────────────────────────────────────────────
    # extract_personality_traits
    # ──────────────────────────────────────────────────────────────────────

    def extract_personality_traits(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Estimate Big Five + Dark Triad scores from online behaviour signals.

        Maps observable online behaviours (post frequency, language patterns,
        social interaction style, content diversity) to OCEAN personality
        dimensions and Dark Triad traits using weighted signal scoring.

        Research basis:
          - Big Five language markers: Pennebaker & King (1999), Tausczik & Pennebaker (2010)
          - Dark Triad online behaviour: Garcia & Sikstrom (2014), Sumner et al. (2012)
          - Twitter personality prediction: Golbeck et al. (2011), Quercia et al. (2012)

        Args:
            profile_data: Aggregated profile data from _aggregate_source_data.

        Returns:
            Dict with OCEAN, Dark Triad, and metadata keys.
        """
        traits: Dict[str, float] = {
            "openness": 0.5,
            "conscientiousness": 0.5,
            "extraversion": 0.5,
            "agreeableness": 0.5,
            "neuroticism": 0.5,
            "narcissism": 0.2,
            "machiavellianism": 0.2,
            "psychopathy": 0.1,
        }

        evidence_count = 0
        writing = profile_data.get("_writing_style", {})

        # ── Big Five from behavioural signals ──
        for trait_name in self.BIG_FIVE:
            signals = _BIG_FIVE_SIGNALS.get(trait_name, {})
            adjustments: List[float] = []

            # ── Linguistic signals from writing style ──
            if writing:
                adjustments.extend(
                    self._big_five_linguistic_signals(trait_name, writing)
                )

            # ── Behavioural signals from profile data ──
            adjustments.extend(
                self._big_five_behavioural_signals(trait_name, profile_data)
            )

            if adjustments:
                base = 0.5
                net_adjustment = sum(adjustments)
                # Clamp adjustment to prevent runaway values
                net_adjustment = max(-0.4, min(0.4, net_adjustment))
                traits[trait_name] = max(0.05, min(0.95, base + net_adjustment))
                evidence_count += len(adjustments)

        # ── Dark Triad from language + behaviour ──
        for triad_trait in self.DARK_TRIAD:
            triad_score = self._estimate_dark_triad(triad_trait, profile_data, writing)
            traits[triad_trait] = max(0.0, min(1.0, triad_score))

        traits["_confidence"] = self._compute_confidence(evidence_count, profile_data)
        traits["_evidence_count"] = evidence_count

        logger.info(
            "Personality traits: O=%.2f C=%.2f E=%.2f A=%.2f N=%.2f | "
            "DT: NARC=%.2f MACH=%.2f PSY=%.2f (evidence=%d, conf=%.2f)",
            traits["openness"], traits["conscientiousness"],
            traits["extraversion"], traits["agreeableness"], traits["neuroticism"],
            traits["narcissism"], traits["machiavellianism"], traits["psychopathy"],
            evidence_count, traits["_confidence"],
        )

        return traits

    # ──────────────────────────────────────────────────────────────────────
    # find_cognitive_biases
    # ──────────────────────────────────────────────────────────────────────

    def find_cognitive_biases(self, profile_data: Dict[str, Any]) -> Dict[str, float]:
        """Identify which cognitive biases the person is susceptible to.

        Scores each of the eight persuasion-relevant biases by analyzing:
          - Language patterns in the person's writing
          - Role/position within the organization
          - Personality trait interactions
          - Behavioural history (responses to urgency, authority, etc.)

        Each bias scored 0.0 (low susceptibility) to 1.0 (high susceptibility).

        Args:
            profile_data: Aggregated profile data from _aggregate_source_data.

        Returns:
            Dict[str, float] mapping bias name to susceptibility score.
        """
        biases: Dict[str, float] = {}
        writing = profile_data.get("_writing_style", {})
        texts = profile_data.get("texts", [])
        combined_text = " ".join(texts).lower() if texts else ""
        roles = profile_data.get("roles", [])
        role_str = " ".join(roles).lower() if roles else ""

        for bias_name, bias_def in _BIAS_INDICATORS.items():
            score = 0.0
            signals = 0

            # ── Keyword presence in target's own writing ──
            kw_matches = sum(
                1 for kw in bias_def.get("keywords", [])
                if kw.lower() in combined_text
            )
            if kw_matches > 0:
                # More keyword matches → more likely susceptible
                kw_score = min(1.0, kw_matches / max(len(bias_def["keywords"]) * 0.1, 1))
                score += kw_score * 0.25
                signals += 1

            # ── Role-based susceptibility ──
            role_weights = bias_def.get("role_weights", {})
            for role, weight in role_weights.items():
                if role.lower() in role_str:
                    score += weight * 0.20
                    signals += 1
                    break

            # ── Personality-trait interaction ──
            trait_score = self._bias_from_traits(bias_name, profile_data)
            if trait_score is not None:
                score += trait_score * 0.25
                signals += 1

            # ── Writing style signals ──
            style_score = self._bias_from_writing_style(bias_name, writing)
            if style_score is not None:
                score += style_score * 0.15
                signals += 1

            # ── Behavioural indicators from profile data ──
            behav_score = self._bias_from_behaviour(bias_name, profile_data)
            if behav_score is not None:
                score += behav_score * 0.15
                signals += 1

            # ── Normalize ──
            if signals > 0:
                # Weight by evidence; low signal count → regress to prior
                prior = 0.3
                evidence_weight = min(1.0, signals / 4.0)
                biases[bias_name] = round(prior + (score - prior) * evidence_weight, 4)
            else:
                biases[bias_name] = round(0.2, 4)  # default low susceptibility

        # ── Clamp ──
        biases = {k: max(0.0, min(1.0, v)) for k, v in biases.items()}

        top_biases = sorted(biases.items(), key=lambda x: x[1], reverse=True)[:3]
        logger.info("Top cognitive biases: %s",
                     [(b, round(s, 2)) for b, s in top_biases])

        return biases

    # ──────────────────────────────────────────────────────────────────────
    # find_optimal_attack_vector
    # ──────────────────────────────────────────────────────────────────────

    def find_optimal_attack_vector(self, profile: Dict[str, Any]) -> Dict[str, Any]:
        """Match psychological vulnerabilities to social engineering attack vectors.

        Evaluates all attack vectors against the target's personality profile,
        ranking them by expected effectiveness. Considers:
          - Bias exploitability (does the target have the biases this vector needs?)
          - Trait compatibility (do the target's OCEAN/Dark Triad traits align?)
          - Contextual factors (role, organization, security awareness)

        Args:
            profile: Complete psychological profile dict (from profile_person).

        Returns:
            Dict with ranked attack vectors and top recommendation.
        """
        big_five = profile.get("big_five", {})
        dark_triad = profile.get("dark_triad", {})
        biases = profile.get("biases", {})

        scored_vectors: List[Dict[str, Any]] = []

        for vector_name, vector_def in _ATTACK_VECTORS.items():
            score = vector_def.get("effectiveness", 0.5)  # base effectiveness
            adjustments: List[float] = []

            # ── Bias exploitability ──
            exploited_biases = vector_def.get("exploits", [])
            for bias_name in exploited_biases:
                bias_score = biases.get(bias_name, 0.3)
                # High bias score → more exploitable
                adjustments.append((bias_score - 0.3) * 0.30)

            # ── Trait compatibility ──
            required_traits = vector_def.get("traits", {})
            for trait, desired in required_traits.items():
                actual = big_five.get(trait, 0.5)
                if desired == "high" and actual > 0.6:
                    adjustments.append(0.10)
                elif desired == "low" and actual < 0.4:
                    adjustments.append(0.10)
                elif desired == "any":
                    adjustments.append(0.02)

            required_dark = vector_def.get("dark_triad", {})
            for trait, desired in required_dark.items():
                actual = dark_triad.get(trait, 0.1)
                if desired == "high" and actual > 0.5:
                    adjustments.append(0.15)

            # ── Compute final score ──
            final_score = score + sum(adjustments)
            final_score = max(0.0, min(1.0, final_score))

            scored_vectors.append({
                "vector": vector_name,
                "score": round(final_score, 4),
                "description": vector_def["description"],
                "recommended_personas": vector_def.get("personas", []),
                "exploited_biases": exploited_biases,
            })

        # ── Sort by score descending ──
        scored_vectors.sort(key=lambda v: v["score"], reverse=True)

        best = scored_vectors[0]
        logger.info(
            "Optimal attack vector: %s (score=%.3f) — %s",
            best["vector"], best["score"], best["description"],
        )

        return {
            "target": profile.get("name", "Unknown"),
            "top_vector": best,
            "all_vectors_ranked": scored_vectors,
            "recommended_approach": (
                f"Use {best['vector']} targeting {best['exploited_biases']}. "
                f"Personas: {best['recommended_personas'][:3]}."
            ),
        }

    # ──────────────────────────────────────────────────────────────────────
    # generate_personalized_phish
    # ──────────────────────────────────────────────────────────────────────

    def generate_personalized_phish(
        self, profile: Dict[str, Any], scenario: str = "password_reset"
    ) -> str:
        """Generate a phishing email specifically tailored to a person's psychology.

        Uses the target's personality profile, cognitive biases, and the optimal
        attack vector to craft a personalized spear-phishing email. The generated
        email adapts tone, urgency, social proof elements, and pretext to match
        the psychological profile for maximum effectiveness.

        Args:
            profile: Complete psychological profile dict.
            scenario: High-level scenario type (password_reset, document_share,
                      meeting_invite, security_alert, executive_request, delivery).

        Returns:
            A complete phishing email as a string (subject + body).
        """
        big_five = profile.get("big_five", {})
        biases = profile.get("biases", {})
        name = profile.get("name", "User")
        org = profile.get("org", "your organization")

        # ── Find best attack vector ──
        attack_plan = self.find_optimal_attack_vector(profile)
        best_vector = attack_plan.get("top_vector", {}).get("vector", "urgency_drive_by")

        # ── Map scenario to attack vector, picking a compatible one ──
        scenario_vector_map = {
            "password_reset": ["urgency_drive_by", "authority_impersonation", "fear_and_intimidation"],
            "document_share": ["curiosity_gap", "reciprocity_trap", "authority_impersonation"],
            "meeting_invite": ["social_proof_cascade", "guilt_and_duty", "reciprocity_trap"],
            "security_alert": ["fear_and_intimidation", "urgency_drive_by", "authority_impersonation"],
            "executive_request": ["authority_impersonation", "guilt_and_duty", "urgency_drive_by"],
            "delivery": ["urgency_drive_by", "curiosity_gap", "scarcity_bias"],
        }
        compatible_vectors = scenario_vector_map.get(scenario, [best_vector])
        if best_vector in compatible_vectors:
            vector = best_vector
        else:
            vector = compatible_vectors[0]

        # ── Select persona ──
        vector_def = _ATTACK_VECTORS.get(vector, _ATTACK_VECTORS["urgency_drive_by"])
        persona = vector_def["personas"][0] if vector_def.get("personas") else "IT Support"

        # ── Extract personalization details ──
        roles = profile.get("roles", [])
        role_hint = roles[0] if roles else "team member"

        # ── Determine tone based on personality ──
        neuroticism = big_five.get("neuroticism", 0.5)
        agreeableness = big_five.get("agreeableness", 0.5)
        conscientiousness = big_five.get("conscientiousness", 0.5)

        # High neuroticism → fear/intimidation tone
        # High agreeableness → friendly/helpful tone
        # High conscientiousness → duty/obligation tone
        if neuroticism > 0.65:
            tone = "fear_based"
        elif agreeableness > 0.65:
            tone = "friendly_helpful"
        elif conscientiousness > 0.65:
            tone = "duty_obligation"
        else:
            tone = "neutral_professional"

        # ── Build subject line ──
        subject = self._craft_subject(vector, persona, org, name, biases)

        # ── Build email body ──
        body = self._craft_body(
            vector=vector,
            persona=persona,
            name=name,
            org=org,
            role=role_hint,
            tone=tone,
            biases=biases,
            big_five=big_five,
            scenario=scenario,
        )

        # ── Assemble full email ──
        phish = (
            f"Subject: {subject}\n"
            f"From: {persona.lower().replace(' ', '.')}@{org.lower().replace(' ', '')}.com\n"
            f"To: {name.lower().replace(' ', '.')}@{org.lower().replace(' ', '')}.com\n"
            f"Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')}\n"
            f"\n{body}\n"
        )

        logger.info("Generated personalized phish for %s: vector=%s tone=%s scenario=%s",
                     name, vector, tone, scenario)

        return phish

    # ──────────────────────────────────────────────────────────────────────
    # profile_organization
    # ──────────────────────────────────────────────────────────────────────

    def profile_organization(
        self, org_name: str, depth: int = 3
    ) -> Dict[str, Any]:
        """Profile an entire organization — org chart, key people, communication patterns.

        Builds a comprehensive organizational psychological map by profiling
        key individuals, analyzing their interactions, and identifying the
        overall psychological climate. The depth parameter controls how many
        levels of the org chart to profile.

        Args:
            org_name: Name of the target organization.
            depth: How many hierarchical levels to include (1=C-suite only,
                   2=+VPs/Directors, 3=+Managers/Leads).

        Returns:
            Org profile dict with org_chart, key_people, vulnerability_map, etc.
        """
        if org_name in self._org_profiles:
            return self._org_profiles[org_name]

        logger.info("Profiling organization: %s (depth=%d)", org_name, depth)

        # ── Simulate org chart discovery ──
        org_chart = self._discover_org_chart(org_name, depth)

        # ── Profile each key person ──
        key_people = []
        for level_idx, level in enumerate(org_chart.get("levels", [])):
            for person in level.get("members", []):
                profile = self.profile_person(
                    person["name"], org_name,
                    sources=person.get("sources", ["linkedin", "twitter"]),
                )
                key_people.append({
                    "name": person["name"],
                    "title": person.get("title", ""),
                    "level": level_idx,
                    "profile": profile,
                })

        # ── Communication patterns ──
        comm_patterns = self._analyze_comm_patterns(key_people, org_name)

        # ── Vulnerability map ──
        vuln_map = self.get_org_vulnerability_map({"key_people": key_people, "org_name": org_name})

        # ── Assemble ──
        org_profile = {
            "org_name": org_name,
            "profiled_at": datetime.now(timezone.utc).isoformat(),
            "depth": depth,
            "people_count": len(key_people),
            "org_chart": org_chart,
            "key_people": key_people,
            "communication_patterns": comm_patterns,
            "vulnerability_map": vuln_map,
        }

        self._org_profiles[org_name] = org_profile
        logger.info("Organization profile complete: %s (%d people, depth=%d)",
                     org_name, len(key_people), depth)

        return org_profile

    # ──────────────────────────────────────────────────────────────────────
    # get_org_vulnerability_map
    # ──────────────────────────────────────────────────────────────────────

    def get_org_vulnerability_map(
        self, org_profile: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Which people are the weakest links? Ranked by psychological susceptibility.

        Ranks every profiled person in the organization by their exploitability
        score — a composite of their worst bias susceptibility, trait
        vulnerabilities, and role-based access value. The weakest link is the
        person with the highest composite score.

        Args:
            org_profile: Dict with at minimum {"key_people": [...], "org_name": "..."}.

        Returns:
            VulnerabilityMap dict with rankings, weakest_link, etc.
        """
        key_people = org_profile.get("key_people", [])
        org_name = org_profile.get("org_name", "Unknown")

        if not key_people:
            logger.warning("No key people in org profile for vulnerability mapping")
            return VulnerabilityMap(org_name=org_name).__dict__

        rankings: List[Dict[str, Any]] = []

        for person in key_people:
            profile = person.get("profile", {})
            big_five = profile.get("big_five", {})
            dark_triad = profile.get("dark_triad", {})
            biases = profile.get("biases", {})

            # ── Psychological susceptibility score ──
            # High neuroticism + high agreeableness + high bias scores = more exploitable
            psy_score = 0.0
            psy_score += big_five.get("neuroticism", 0.5) * 0.25
            psy_score += big_five.get("agreeableness", 0.5) * 0.20
            psy_score += (1.0 - big_five.get("conscientiousness", 0.5)) * 0.15
            psy_score += dark_triad.get("narcissism", 0.1) * 0.15  # ego-stroking vector

            # Highest bias drives susceptibility
            if biases:
                psy_score += max(biases.values()) * 0.25

            psy_score = max(0.0, min(1.0, psy_score))

            # ── Access value (how valuable is this person as an entry point?) ──
            level = person.get("level", 2)
            title = person.get("title", "").lower()
            access_value = 0.5
            if level == 0:  # C-suite
                access_value = 1.0
            elif level == 1:  # VP / Director
                access_value = 0.8
            elif level == 2:  # Manager
                access_value = 0.6
            elif "admin" in title or "it " in title or "sys" in title:
                access_value = 0.85  # IT/Admin access
            elif "developer" in title or "engineer" in title:
                access_value = 0.7  # Code access

            # ── Composite score ──
            composite = psy_score * 0.6 + access_value * 0.4

            rankings.append({
                "name": person.get("name", "Unknown"),
                "title": person.get("title", ""),
                "level": level,
                "psychological_susceptibility": round(psy_score, 4),
                "access_value": round(access_value, 4),
                "composite_score": round(composite, 4),
                "top_biases": sorted(biases.items(), key=lambda x: x[1], reverse=True)[:3] if biases else [],
                "recommended_vector": self.find_optimal_attack_vector(profile).get("top_vector", {}).get("vector", "unknown"),
            })

        # ── Sort by composite score descending ──
        rankings.sort(key=lambda r: r["composite_score"], reverse=True)

        weakest_link = rankings[0] if rankings else None
        avg_susceptibility = (
            sum(r["composite_score"] for r in rankings) / len(rankings)
            if rankings else 0.0
        )
        high_risk_count = sum(1 for r in rankings if r["composite_score"] > 0.7)

        logger.info(
            "Org vulnerability map: %s — weakest link: %s (score=%.3f), "
            "avg=%.3f, high-risk=%d/%d",
            org_name,
            weakest_link["name"] if weakest_link else "N/A",
            weakest_link["composite_score"] if weakest_link else 0,
            avg_susceptibility, high_risk_count, len(rankings),
        )

        return {
            "org_name": org_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "rankings": rankings,
            "weakest_link": weakest_link,
            "average_susceptibility": round(avg_susceptibility, 4),
            "high_risk_count": high_risk_count,
            "total_people": len(rankings),
        }

    # ══════════════════════════════════════════════════════════════════════
    # Internal helpers — source aggregation
    # ══════════════════════════════════════════════════════════════════════

    def _aggregate_source_data(
        self, name: str, org: str, sources: List[str]
    ) -> Dict[str, Any]:
        """Simulate gathering profile data from specified public sources.

        In production, this would query real APIs (LinkedIn, Twitter, GitHub,
        etc.) or use OSINT tools. Here we generate realistic simulated data
        for each source type, sufficient to drive the downstream NLP and trait
        extraction pipelines.
        """
        data: Dict[str, Any] = {
            "name": name,
            "org": org,
            "roles": [],
            "texts": [],
            "interests": [],
            "skills": [],
            "activity": {},
            "connections": 0,
        }

        name_hash = hashlib.md5(name.encode()).digest()
        seed = int.from_bytes(name_hash[:4], "big")

        # Deterministic random based on name for reproducibility
        rng = random.Random(seed)

        # ── LinkedIn ──
        if "linkedin" in sources:
            roles = rng.choice([
                ["Software Engineer", "Senior Developer"],
                ["Product Manager", "Director of Product"],
                ["Marketing Manager", "Brand Strategist"],
                ["IT Administrator", "Systems Engineer"],
                ["Chief Technology Officer"],
                ["Chief Financial Officer"],
                ["VP of Engineering"],
                ["Data Scientist", "ML Engineer"],
                ["Security Analyst", "SOC Lead"],
                ["HR Manager", "People Operations"],
                ["Sales Director", "Account Executive"],
                ["Legal Counsel", "Compliance Officer"],
            ])
            data["roles"].extend(roles)
            data["texts"].append(
                f"Experienced {roles[0]} at {org}. Passionate about "
                f"{rng.choice(['technology', 'innovation', 'leadership', 'building teams', 'solving complex problems'])}. "
                f"{rng.choice(['Proven track record', 'Dedicated', 'Results-oriented', 'Strategic thinker'])} "
                f"with {rng.randint(5, 20)}+ years of experience."
            )
            data["connections"] = rng.randint(200, 2000)

        # ── Twitter ──
        if "twitter" in sources:
            tweets = []
            for _ in range(rng.randint(3, 10)):
                tweet_type = rng.random()
                if tweet_type < 0.3:
                    tweets.append(
                        f"Just published our {rng.choice(['quarterly results', 'new feature', 'research paper', 'team update'])}. "
                        f"{rng.choice(['Proud of the team!', 'Check it out!', 'Excited to share this.', 'Big milestone today.'])}"
                    )
                elif tweet_type < 0.6:
                    tweets.append(
                        f"{rng.choice(['Hot take:', 'Unpopular opinion:', 'Thinking about:', 'Reading on'])} "
                        f"{rng.choice(['AI ethics', 'remote work', 'security best practices', 'engineering culture', 'blockchain'])}. "
                        f"{rng.choice(['Thoughts?', 'Would love feedback.', 'Am I wrong?', 'Let me know what you think.'])}"
                    )
                else:
                    tweets.append(
                        f"{rng.choice(['Great', 'Interesting', 'Important'])} article on "
                        f"{rng.choice(['cybersecurity', 'machine learning', 'leadership', 'startups', 'cloud computing'])}. "
                        f"{rng.choice(['Must read.', 'Highly recommend.', 'Worth your time.'])}"
                    )
            data["texts"].extend(tweets)
            data["activity"]["post_frequency"] = rng.choice(["daily", "weekly", "monthly", "rarely"])
            data["activity"]["engagement_style"] = rng.choice(["broadcaster", "conversationalist", "lurker", "debater"])

        # ── GitHub ──
        if "github" in sources:
            repos = rng.randint(5, 80)
            data["skills"].extend(
                rng.sample(
                    ["Python", "JavaScript", "Go", "Rust", "Java", "TypeScript",
                     "Kubernetes", "Docker", "React", "AWS", "Terraform", "C++",
                     "Machine Learning", "Security", "DevOps", "Data Engineering"],
                    rng.randint(3, 8),
                )
            )
            data["texts"].append(
                f"{rng.choice(['Building', 'Maintaining', 'Contributing to'])} "
                f"{rng.choice(['open-source tools', 'infrastructure', 'security tooling', 'developer tools', 'data pipelines'])}. "
                f"{repos} public repositories. "
                f"{rng.choice(['Clean code advocate.', 'CI/CD enthusiast.', 'Security-first mindset.', 'Performance obsessed.'])}"
            )
            data["activity"]["github_repos"] = repos
            data["activity"]["github_contributions"] = rng.randint(50, 2000)

        # ── Blog ──
        if "blog" in sources:
            blog_posts = []
            for _ in range(rng.randint(1, 4)):
                blog_posts.append(self._generate_blog_post(rng, org))
            data["texts"].extend(blog_posts)
            data["activity"]["has_blog"] = True

        # ── Talks / Conferences ──
        if "talks" in sources or "papers" in sources:
            data["texts"].append(
                f"In this {rng.choice(['talk', 'paper', 'presentation'])}, "
                f"we explore {rng.choice(['the intersection of', 'novel approaches to', 'practical applications of'])} "
                f"{rng.choice(['AI', 'security', 'distributed systems', 'data privacy'])}. "
                f"{rng.choice(['Our findings suggest', 'The evidence shows', 'We demonstrate'])} "
                f"that {rng.choice(['there is significant room for improvement',
                                     'current approaches are insufficient',
                                     'a paradigm shift is needed'])}."
            )

        # ── Reddit / Forums ──
        if "reddit" in sources:
            data["interests"].extend(
                rng.sample(
                    ["technology", "programming", "cybersecurity", "investing",
                     "gaming", "photography", "hiking", "cooking", "music",
                     "fitness", "philosophy", "science", "history"],
                    rng.randint(3, 6),
                )
            )

        # ── Stack Overflow ──
        if "stackoverflow" in sources:
            data["texts"].append(
                f"{rng.choice(['How do I', 'What is the best way to', 'Can someone explain'])} "
                f"{rng.choice(['deploy', 'secure', 'optimize', 'debug', 'scale'])} "
                f"{rng.choice(['a Kubernetes cluster', 'React state management', 'Python async', 'Terraform modules'])}?"
            )

        return data

    def _generate_blog_post(self, rng: random.Random, org: str) -> str:
        """Generate a realistic blog-post text sample."""
        topics = [
            f"How we {rng.choice(['scaled', 'secured', 'migrated', 'optimized'])} "
            f"{rng.choice(['our infrastructure', 'the monolith', 'our CI/CD pipeline', 'the data layer'])} at {org}",
            f"Lessons learned from {rng.randint(2, 5)} years of "
            f"{rng.choice(['building products', 'leading engineering teams', 'remote work', 'startup life'])}",
            f"Why {rng.choice(['we chose', 'we moved away from', 'we invested in'])} "
            f"{rng.choice(['Kubernetes', 'microservices', 'TypeScript', 'GraphQL', 'Rust'])}",
        ]
        topic = rng.choice(topics)
        return (
            f"{topic}. Over the past {rng.randint(1, 3)} years, our team has "
            f"{rng.choice(['learned a lot', 'faced many challenges', 'made significant progress'])}. "
            f"{rng.choice(['The key insight was', 'What surprised us most was', 'The biggest takeaway is'])} "
            f"that {rng.choice(['simplicity wins', 'culture eats strategy', 'security cannot be an afterthought',
                                'investing in developer experience pays off', 'you need to measure what matters'])}. "
            f"{rng.choice(['I would love to hear your thoughts.', 'What has your experience been?',
                           'Would recommend this approach to anyone facing similar challenges.'])}"
        )

    # ══════════════════════════════════════════════════════════════════════
    # Internal helpers — Big Five signal extraction
    # ══════════════════════════════════════════════════════════════════════

    def _big_five_linguistic_signals(
        self, trait: str, writing: Dict[str, Any]
    ) -> List[float]:
        """Extract Big Five adjustments from writing style metrics."""
        adjustments: List[float] = []

        if trait == "openness":
            # High vocabulary + high complexity + creative language → high openness
            if writing.get("vocabulary_level", 0.5) > 0.65:
                adjustments.append(0.08)
            if writing.get("type_token_ratio", 0.5) > 0.6:
                adjustments.append(0.06)
            if writing.get("complexity_score", 0.5) > 0.6:
                adjustments.append(0.05)

        elif trait == "conscientiousness":
            # High formality + low errors + structured → high conscientiousness
            if writing.get("formality_score", 0.5) > 0.6:
                adjustments.append(0.08)
            if writing.get("punctuation_formality", 0.5) > 0.6:
                adjustments.append(0.06)
            # High hedge ratio → lower conscientiousness (indecisive)
            if writing.get("hedge_ratio", 0.0) > 0.03:
                adjustments.append(-0.06)

        elif trait == "extraversion":
            # High social reference + exclamation + positive emotion → high extraversion
            if writing.get("social_reference_ratio", 0.0) > 0.02:
                adjustments.append(0.10)
            if writing.get("exclamation_frequency", 0.0) > 0.1:
                adjustments.append(0.07)
            emo = writing.get("emotional_tone", {})
            if emo.get("positive", 0.3) > 0.4:
                adjustments.append(0.06)

        elif trait == "agreeableness":
            # Low anger + high positive + polite → high agreeableness
            emo = writing.get("emotional_tone", {})
            if emo.get("anger", 0.0) < 0.05:
                adjustments.append(0.06)
            if emo.get("positive", 0.3) > 0.35:
                adjustments.append(0.05)
            if writing.get("certainty_ratio", 0.0) < 0.02:
                adjustments.append(0.04)  # less dogmatic

        elif trait == "neuroticism":
            # High negative emotion + high anxiety + high self-reference → high neuroticism
            emo = writing.get("emotional_tone", {})
            if emo.get("negative", 0.2) > 0.3:
                adjustments.append(0.10)
            if emo.get("fear", 0.0) > 0.05:
                adjustments.append(0.08)
            if emo.get("sadness", 0.0) > 0.05:
                adjustments.append(0.06)
            if writing.get("self_reference_ratio", 0.03) > 0.05:
                adjustments.append(0.05)

        return adjustments

    def _big_five_behavioural_signals(
        self, trait: str, profile_data: Dict[str, Any]
    ) -> List[float]:
        """Extract Big Five adjustments from behavioural profile data."""
        adjustments: List[float] = []
        texts = profile_data.get("texts", [])
        all_text = " ".join(texts).lower()
        interests = [i.lower() for i in profile_data.get("interests", [])]
        roles = [r.lower() for r in profile_data.get("roles", [])]
        activity = profile_data.get("activity", {})

        if trait == "openness":
            # Diverse interests → higher openness
            if len(interests) >= 5:
                adjustments.append(0.10)
            if any(w in all_text for w in ["curious", "explore", "discover", "novel", "creative"]):
                adjustments.append(0.07)
            if activity.get("engagement_style") == "debater":
                adjustments.append(0.05)

        elif trait == "conscientiousness":
            if any(w in all_text for w in ["deadline", "schedule", "organized", "process", "methodology"]):
                adjustments.append(0.08)
            if activity.get("post_frequency") == "daily":
                adjustments.append(0.04)
            if "Manager" in str(roles) or "Director" in str(roles) or "Lead" in str(roles):
                adjustments.append(0.05)

        elif trait == "extraversion":
            if activity.get("engagement_style") in ("broadcaster", "conversationalist"):
                adjustments.append(0.10)
            if activity.get("post_frequency") in ("daily", "weekly"):
                adjustments.append(0.08)
            if profile_data.get("connections", 0) > 500:
                adjustments.append(0.06)

        elif trait == "agreeableness":
            if any(w in all_text for w in ["team", "collaborate", "together", "support", "help"]):
                adjustments.append(0.08)
            if activity.get("engagement_style") == "conversationalist":
                adjustments.append(0.06)

        elif trait == "neuroticism":
            if any(w in all_text for w in ["worried", "stressed", "anxious", "concerned", "overwhelmed"]):
                adjustments.append(0.10)
            if any(w in all_text for w in ["failure", "mistake", "wrong", "problem"]):
                adjustments.append(0.06)

        return adjustments

    # ══════════════════════════════════════════════════════════════════════
    # Internal helpers — Dark Triad estimation
    # ══════════════════════════════════════════════════════════════════════

    def _estimate_dark_triad(
        self, trait: str, profile_data: Dict[str, Any], writing: Dict[str, Any]
    ) -> float:
        """Estimate a single Dark Triad trait from language and behaviour."""
        indicators = _DARK_TRIAD_INDICATORS.get(trait, {})
        keywords = indicators.get("keywords", [])
        texts = profile_data.get("texts", [])
        all_text = " ".join(texts).lower()

        score = 0.1  # low base rate for Dark Triad traits
        signals = 0

        # ── Keyword density ──
        kw_count = sum(1 for kw in keywords if kw.lower() in all_text)
        total_words = len(all_text.split()) or 1
        kw_density = kw_count / total_words
        if kw_density > 0.01:
            score += min(0.4, kw_density * 20)
            signals += 1

        # ── Trait-specific signals ──
        if trait == "narcissism":
            self_ref = writing.get("self_reference_ratio", 0.03)
            if self_ref > 0.06:
                score += 0.20
                signals += 1
            if writing.get("certainty_ratio", 0.0) > 0.03:
                score += 0.10
                signals += 1

        elif trait == "machiavellianism":
            if any(w in all_text for w in ["leverage", "influence", "power", "control"]):
                score += 0.15
                signals += 1
            if writing.get("formality_score", 0.5) > 0.7:
                score += 0.08
                signals += 1

        elif trait == "psychopathy":
            emo = writing.get("emotional_tone", {})
            # Low empathy → low sadness + low fear in language
            if emo.get("sadness", 0.1) < 0.05 and emo.get("fear", 0.1) < 0.05:
                score += 0.10
                signals += 1
            if writing.get("exclamation_frequency", 0.0) > 0.15:
                score += 0.08  # impulsivity signal
                signals += 1
            if any(w in all_text for w in ["don't care", "whatever", "bored", "thrill"]):
                score += 0.15
                signals += 1

        # ── Normalize by evidence ──
        if signals > 0:
            evidence_weight = min(1.0, signals / 3.0)
            score = 0.1 + (score - 0.1) * evidence_weight

        return min(1.0, score)

    # ══════════════════════════════════════════════════════════════════════
    # Internal helpers — cognitive bias detection
    # ══════════════════════════════════════════════════════════════════════

    def _bias_from_traits(
        self, bias_name: str, profile_data: Dict[str, Any]
    ) -> Optional[float]:
        """Score bias susceptibility from personality trait interactions."""
        big_five = profile_data.get("_traits", {})
        if not big_five:
            return None

        mapping = {
            "authority_bias": (
                (1.0 - big_five.get("openness", 0.5)) * 0.3
                + big_five.get("agreeableness", 0.5) * 0.3
            ),
            "urgency_bias": (
                big_five.get("neuroticism", 0.5) * 0.4
                + big_five.get("conscientiousness", 0.5) * 0.2
            ),
            "curiosity_bias": big_five.get("openness", 0.5) * 0.6,
            "reciprocity_bias": big_five.get("agreeableness", 0.5) * 0.5,
            "confirmation_bias": (
                (1.0 - big_five.get("openness", 0.5)) * 0.4
                + big_five.get("conscientiousness", 0.5) * 0.2
            ),
            "social_proof": (
                big_five.get("extraversion", 0.5) * 0.3
                + big_five.get("agreeableness", 0.5) * 0.2
            ),
            "scarcity_bias": (
                big_five.get("neuroticism", 0.5) * 0.3
                + (1.0 - big_five.get("conscientiousness", 0.5)) * 0.2
            ),
            "liking_bias": (
                big_five.get("agreeableness", 0.5) * 0.3
                + big_five.get("extraversion", 0.5) * 0.2
            ),
        }

        return mapping.get(bias_name)

    def _bias_from_writing_style(
        self, bias_name: str, writing: Dict[str, Any]
    ) -> Optional[float]:
        """Score bias susceptibility from writing style features."""
        if not writing:
            return None

        mapping = {
            "authority_bias": (
                0.4 if writing.get("certainty_ratio", 0.0) < 0.01 else 0.2
            ),
            "urgency_bias": (
                0.5 if writing.get("exclamation_frequency", 0.0) > 0.1 else 0.2
            ),
            "curiosity_bias": (
                0.5 if writing.get("question_frequency", 0.0) > 0.2 else 0.2
            ),
            "reciprocity_bias": (
                0.4 if writing.get("social_reference_ratio", 0.0) > 0.02 else 0.2
            ),
            "confirmation_bias": (
                0.4 if writing.get("certainty_ratio", 0.0) > 0.03 else 0.2
            ),
            "social_proof": (
                0.5 if writing.get("social_reference_ratio", 0.0) > 0.03 else 0.2
            ),
            "scarcity_bias": (
                0.4 if writing.get("exclamation_frequency", 0.0) > 0.15 else 0.2
            ),
            "liking_bias": (
                0.4 if writing.get("emotional_tone", {}).get("positive", 0.0) > 0.3 else 0.2
            ),
        }

        return mapping.get(bias_name)

    def _bias_from_behaviour(
        self, bias_name: str, profile_data: Dict[str, Any]
    ) -> Optional[float]:
        """Score bias susceptibility from behavioural indicators."""
        activity = profile_data.get("activity", {})
        if not activity:
            return None

        mapping = {
            "authority_bias": (
                0.6 if activity.get("engagement_style") == "lurker" else
                0.3 if activity.get("engagement_style") == "conversationalist" else 0.4
            ),
            "urgency_bias": (
                0.6 if activity.get("post_frequency") == "daily" else 0.4
            ),
            "curiosity_bias": (
                0.6 if activity.get("engagement_style") == "debater" else
                0.5 if activity.get("has_blog") else 0.3
            ),
            "social_proof": (
                0.7 if activity.get("engagement_style") == "broadcaster" else
                0.5 if activity.get("post_frequency") in ("daily", "weekly") else 0.3
            ),
            "liking_bias": (
                0.5 if activity.get("engagement_style") == "conversationalist" else 0.3
            ),
            "scarcity_bias": (
                0.5 if activity.get("post_frequency") == "daily" else 0.3
            ),
            "reciprocity_bias": (
                0.5 if activity.get("engagement_style") == "conversationalist" else 0.3
            ),
            "confirmation_bias": (
                0.5 if activity.get("engagement_style") == "debater" else 0.3
            ),
        }

        return mapping.get(bias_name)

    # ══════════════════════════════════════════════════════════════════════
    # Internal helpers — phishing generation
    # ══════════════════════════════════════════════════════════════════════

    def _craft_subject(
        self, vector: str, persona: str, org: str, name: str, biases: Dict[str, float]
    ) -> str:
        """Craft a subject line tuned to the vector and biases."""
        top_bias = max(biases, key=biases.get) if biases else "urgency_bias"

        subjects = {
            "authority_impersonation": [
                f"URGENT: Security verification required - {org} IT",
                f"[{org}] Mandatory account review from {persona}",
                f"Action Required: {persona} requests credential verification",
            ],
            "urgency_drive_by": [
                f"⚠️ Your {org} account will be suspended in 24 hours",
                f"ACTION REQUIRED: Password expires today",
                f"URGENT: Unusual login detected on your {org} account",
            ],
            "curiosity_gap": [
                f"Confidential: What I discovered about {org}",
                f"You're mentioned in this leaked {org} document",
                f"I shouldn't share this, but... (re: {org})",
            ],
            "reciprocity_trap": [
                f"Resources I put together for you re: {org}",
                f"Thanks for your work — sharing something in return",
                f"Thought you'd find this useful, {name}",
            ],
            "social_proof_cascade": [
                f"Join your {org} colleagues already on the platform",
                f"Your team at {org} is waiting for you",
                f"500+ {org} employees have already signed up",
            ],
            "liking_and_similarity": [
                f"Hey {name}, fellow enthusiast here",
                f"Re: our shared interest — check this out!",
                f"Thought of you when I saw this",
            ],
            "fear_and_intimidation": [
                f"[{org}] OFFICIAL NOTICE: Non-compliance flagged",
                f"LEGAL: Your {org} account under review",
                f"NOTICE: Regulatory inquiry regarding your {org} access",
            ],
            "ego_stroking": [
                f"You've been nominated — {org} Excellence Award",
                f"Exclusive opportunity for {name} at {org}",
                f"Your {org} work caught our attention",
            ],
            "guilt_and_duty": [
                f"Team is blocked waiting on your input — {org}",
                f"{name}, we need your section by EOD",
                f"Quick review needed — the {org} team is counting on you",
            ],
        }

        options = subjects.get(vector, subjects["urgency_drive_by"])

        # Pick based on top bias if relevant vector matches
        name_hash = hashlib.md5(name.encode()).digest()
        idx = name_hash[0] % len(options)
        return options[idx]

    def _craft_body(
        self,
        vector: str,
        persona: str,
        name: str,
        org: str,
        role: str,
        tone: str,
        biases: Dict[str, float],
        big_five: Dict[str, float],
        scenario: str,
    ) -> str:
        """Craft the full email body with psychological tailoring."""
        openings = _PHISH_OPENINGS.get(vector, _PHISH_OPENINGS["urgency_drive_by"])
        closers = _PHISH_CLOSERS.get(vector, _PHISH_CLOSERS["urgency_drive_by"])

        name_hash = hashlib.md5(name.encode()).digest()
        idx_open = name_hash[1] % len(openings)
        idx_close = name_hash[2] % len(closers)

        # ── Build personalization variables ──
        top_bias_name = max(biases, key=biases.get) if biases else "urgency_bias"
        interests = ["technology", "leadership", "innovation", "security"]
        shared_interest = interests[name_hash[3] % len(interests)]

        vars_dict = {
            "name": name.split()[0] if " " in name else name,
            "org": org,
            "persona": persona,
            "role": role,
            "shared_interest": shared_interest,
            "service": f"{org} Secure Portal",
            "time_window": "24 hours",
            "deadline": "today at 5 PM",
            "count": str(500 + name_hash[4] % 500),
            "document_type": "Q4 strategy document",
            "topic": "engineering leadership",
            "project": f"{org.split()[0]} migration",
            "publication": "Industry Leader Magazine",
            "award": "Innovation Excellence Award",
            "event": f"{org.split()[0]} Tech Summit 2024",
            "resource": "exclusive whitepaper",
        }

        opening = openings[idx_open].format(**vars_dict)
        closing = closers[idx_close].format(**vars_dict)

        # ── Middle paragraph tuned to personality ──
        middle = self._craft_middle_paragraph(
            vector, top_bias_name, tone, big_five, vars_dict
        )

        # ── CTA (call-to-action) tune ──
        cta = self._craft_cta(tone, top_bias_name, vars_dict)

        return (
            f"Hi {vars_dict['name']},\n\n"
            f"{opening}\n\n"
            f"{middle}\n\n"
            f"{closing}\n\n"
            f"{cta}\n\n"
            f"Best,\n"
            f"{persona}"
        )

    def _craft_middle_paragraph(
        self,
        vector: str,
        top_bias: str,
        tone: str,
        big_five: Dict[str, float],
        vars_dict: Dict[str, str],
    ) -> str:
        """Craft the persuasive middle paragraph."""
        neuroticism = big_five.get("neuroticism", 0.5)
        agreeableness = big_five.get("agreeableness", 0.5)

        paragraphs = {
            ("authority_impersonation", "fear_based"): (
                f"Per {vars_dict['org']} security policy Section 4.2, all personnel must "
                f"complete mandatory credential verification quarterly. Your account "
                f"has been randomly selected for audit. Failure to complete this "
                f"verification within the specified window may result in temporary "
                f"access suspension pending manual review."
            ),
            ("authority_impersonation", "friendly_helpful"): (
                f"As part of our ongoing effort to keep {vars_dict['org']} secure, "
                f"we're conducting routine access reviews. Your account was selected "
                f"and we want to make this as smooth as possible for you. "
                f"It should only take two minutes."
            ),
            ("urgency_drive_by", "fear_based"): (
                f"Our monitoring systems detected unusual activity originating from "
                f"an unrecognized location. To prevent potential account compromise, "
                f"immediate identity verification is required. If not completed "
                f"within {vars_dict['time_window']}, your account will be locked "
                f"as a precautionary measure."
            ),
            ("urgency_drive_by", "duty_obligation"): (
                f"To maintain compliance and ensure uninterrupted access to "
                f"{vars_dict['org']} systems, please complete the verification "
                f"below. This is a time-sensitive requirement that affects your "
                f"ability to access critical resources."
            ),
            ("curiosity_gap", "neutral_professional"): (
                f"I came across something during a research project that directly "
                f"references your work at {vars_dict['org']}. Given the sensitivity, "
                f"I wanted to share it privately before it becomes public. "
                f"I think you'll find it quite interesting."
            ),
            ("reciprocity_trap", "friendly_helpful"): (
                f"I put together these {vars_dict['resource']}s based on our shared "
                f"interest in {vars_dict['shared_interest']}. No strings attached — "
                f"I genuinely think you'll find them valuable. I know how hard it is "
                f"to find quality resources in this space."
            ),
            ("social_proof_cascade", "neutral_professional"): (
                f"Over {vars_dict['count']} professionals from {vars_dict['org']} "
                f"are already using the platform, including several members of your "
                f"team. The feedback has been overwhelmingly positive, and we wanted "
                f"to make sure you had early access."
            ),
            ("fear_and_intimidation", "fear_based"): (
                f"REGULATORY NOTICE: Our automated compliance system has flagged "
                f"a discrepancy in your {vars_dict['org']} access records. Per "
                f"regulatory requirements, this matter requires your immediate "
                f"attention. Please note that non-response will be documented "
                f"and may be escalated."
            ),
            ("ego_stroking", "friendly_helpful"): (
                f"Your contributions to {vars_dict['topic']} at {vars_dict['org']} "
                f"have not gone unnoticed. Several industry leaders specifically "
                f"mentioned your work, and we believe your perspective would be "
                f"invaluable. This is a selective opportunity."
            ),
            ("guilt_and_duty", "duty_obligation"): (
                f"The {vars_dict['project']} timeline depends on your section, and "
                f"we're approaching a critical milestone. The team has been working "
                f"around the clock, and your input is the last piece we need. "
                f"I know you've got a lot on your plate — this shouldn't take long."
            ),
        }

        # ── Fallback: build generic middle tuned to top bias ──
        return paragraphs.get(
            (vector, tone),
            self._generic_middle(top_bias, vars_dict),
        )

    def _generic_middle(self, bias: str, vars_dict: Dict[str, str]) -> str:
        """Fallback middle paragraph when no exact template matches."""
        generics = {
            "authority_bias": (
                f"As mandated by {vars_dict['org']} leadership, all team members "
                f"must complete this verification to ensure continued compliance."
            ),
            "urgency_bias": (
                f"This requires your immediate attention. The window for action "
                f"is closing quickly and we need your response today."
            ),
            "curiosity_bias": (
                f"I can't share all the details here, but this is something you'll "
                f"definitely want to see. I'll explain more when you reply."
            ),
            "reciprocity_bias": (
                f"I've shared some resources that took me a while to compile. "
                f"Would love to hear your thoughts when you have a moment."
            ),
            "social_proof": (
                f"Many of your colleagues at {vars_dict['org']} have already "
                f"participated. We wanted to extend the invitation to you as well."
            ),
            "scarcity_bias": (
                f"This opportunity is available for a limited time only. "
                f"We can only accommodate a small number of participants."
            ),
            "liking_bias": (
                f"I've been following your work and we seem to share a lot of "
                f"common interests. I thought you'd appreciate this."
            ),
            "confirmation_bias": (
                f"As someone who understands the importance of {vars_dict['topic']}, "
                f"you'll immediately see the value in what we're building."
            ),
        }
        return generics.get(
            bias,
            f"Please review and take action at your earliest convenience.",
        )

    def _craft_cta(
        self, tone: str, top_bias: str, vars_dict: Dict[str, str]
    ) -> str:
        """Craft the call-to-action line."""
        _ANY = "__any__"
        ctas = {
            ("fear_based", "authority_bias"): (
                f"→ Verify Now: https://{vars_dict['org'].lower().replace(' ', '')}-secure.com/verify"
            ),
            ("fear_based", "urgency_bias"): (
                f"→ Secure Your Account Immediately: https://{vars_dict['org'].lower().replace(' ', '')}-portal.com/verify"
            ),
            ("duty_obligation", _ANY): (
                f"→ Complete Verification: https://{vars_dict['org'].lower().replace(' ', '')}-portal.com/verify"
            ),
            ("friendly_helpful", "liking_bias"): (
                f"→ Check it out here: https://{vars_dict['org'].lower().replace(' ', '')}-connect.com/share"
            ),
            ("friendly_helpful", _ANY): (
                f"→ Get Started: https://{vars_dict['org'].lower().replace(' ', '')}-portal.com/setup"
            ),
            ("neutral_professional", "curiosity_bias"): (
                f"→ View the document (password protected): https://docs.{vars_dict['org'].lower().replace(' ', '')}-share.com/confidential"
            ),
            ("neutral_professional", "social_proof"): (
                f"→ See what your colleagues are saying: https://{vars_dict['org'].lower().replace(' ', '')}-community.com/reviews"
            ),
        }

        return ctas.get(
            (tone, top_bias),
            ctas.get((tone, _ANY),
            f"→ Click here to proceed: https://{vars_dict['org'].lower().replace(' ', '')}-portal.com/action"),
        )

    # ══════════════════════════════════════════════════════════════════════
    # Internal helpers — org profiling
    # ══════════════════════════════════════════════════════════════════════

    def _discover_org_chart(
        self, org_name: str, depth: int
    ) -> Dict[str, Any]:
        """Simulate org chart discovery via LinkedIn/OSINT."""
        org_hash = hashlib.md5(org_name.encode()).digest()
        rng = random.Random(int.from_bytes(org_hash[:4], "big"))

        titles_by_level = [
            # C-suite
            [
                ("Chief Executive Officer", "CEO"),
                ("Chief Technology Officer", "CTO"),
                ("Chief Financial Officer", "CFO"),
                ("Chief Information Security Officer", "CISO"),
                ("Chief Operating Officer", "COO"),
            ],
            # VP / Director
            [
                ("VP of Engineering", "VP Eng"),
                ("VP of Product", "VP Product"),
                ("Director of IT", "Dir IT"),
                ("Director of Security", "Dir Sec"),
                ("Director of Marketing", "Dir Marketing"),
            ],
            # Manager / Lead
            [
                ("Engineering Manager", "EM"),
                ("Product Manager", "PM"),
                ("IT Manager", "IT Manager"),
                ("Security Lead", "Sec Lead"),
                ("DevOps Lead", "DevOps Lead"),
                ("Team Lead", "TL"),
            ],
        ]

        levels = []
        for level_idx in range(min(depth, len(titles_by_level))):
            titles = titles_by_level[level_idx]
            member_count = rng.randint(1, min(len(titles), 3 if level_idx == 0 else 5))
            members = []
            for _ in range(member_count):
                title, short = rng.choice(titles)
                members.append({
                    "name": f"{rng.choice(['Alex', 'Jordan', 'Morgan', 'Taylor', 'Casey', 'Riley', 'Quinn', 'Avery', 'Cameron', 'Drew'])} "
                            f"{rng.choice(['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez'])}",
                    "title": title,
                    "short_title": short,
                    "sources": rng.sample(
                        ["linkedin", "twitter", "github", "blog", "talks"],
                        rng.randint(2, 4),
                    ),
                })
            levels.append({
                "level": level_idx,
                "label": ["C-Suite", "VP/Director", "Manager/Lead"][level_idx],
                "members": members,
            })

        return {
            "org_name": org_name,
            "levels": levels,
            "total_discovered": sum(len(l["members"]) for l in levels),
        }

    def _analyze_comm_patterns(
        self, key_people: List[Dict[str, Any]], org_name: str
    ) -> Dict[str, Any]:
        """Analyze communication patterns across the organization."""
        if not key_people:
            return {}

        # Aggregate writing styles
        formalities = []
        certainties = []
        for p in key_people:
            writing = p.get("profile", {}).get("_writing_style", {})
            if writing:
                formalities.append(writing.get("formality_score", 0.5))
                certainties.append(writing.get("certainty_ratio", 0.0))

        avg_formality = sum(formalities) / len(formalities) if formalities else 0.5
        avg_certainty = sum(certainties) / len(certainties) if certainties else 0.0

        # Determine org communication culture
        if avg_formality > 0.65:
            culture = "formal_hierarchical"  # respect chain of command
        elif avg_formality < 0.35:
            culture = "casual_flat"  # informal, peer-to-peer
        else:
            culture = "balanced_professional"

        return {
            "culture": culture,
            "avg_formality": round(avg_formality, 4),
            "avg_certainty": round(avg_certainty, 4),
            "description": (
                f"{org_name} communication is {culture.replace('_', ' ')}. "
                f"Formality={avg_formality:.2f}, Certainty={avg_certainty:.4f}. "
                f"This informs whether authority-based or peer-based phishing "
                f"pretexts are more effective."
            ),
        }

    # ══════════════════════════════════════════════════════════════════════
    # Utility helpers
    # ══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Tokenize text into words, stripping punctuation."""
        return re.findall(r"[a-zA-Z0-9']+", text)

    @staticmethod
    def _split_sentences(text: str) -> List[str]:
        """Split text into sentences."""
        return re.split(r'[.!?]+', text)

    @staticmethod
    def _count_syllables(words: List[str]) -> int:
        """Estimate syllable count for a list of words."""
        count = 0
        for word in words:
            word_lower = word.lower()
            if not word_lower:
                continue
            # Count vowel groups
            syllables = len(re.findall(r'[aeiouy]+', word_lower))
            # Adjust for silent 'e'
            if word_lower.endswith('e') and syllables > 1:
                syllables -= 1
            # Ensure at least 1 syllable per word
            count += max(1, syllables)
        return count

    @staticmethod
    def _dale_chall_score(words: List[str], total_sentences: int) -> float:
        """Compute Dale-Chall readability score.

        Formula: 0.1579 * (difficult_words / words * 100) + 0.0496 * (words / sentences)
        """
        if not words or total_sentences == 0:
            return 5.0

        difficult = sum(1 for w in words if w.lower() not in _DALE_CHALL_EASY)
        percent_difficult = (difficult / len(words)) * 100
        avg_sentence_length = len(words) / total_sentences

        raw_score = 0.1579 * percent_difficult + 0.0496 * avg_sentence_length
        # Clamp to reasonable range
        return max(0.0, min(20.0, raw_score))

    @staticmethod
    def _sigmoid(x: float) -> float:
        """Sigmoid activation for normalization."""
        try:
            return 1.0 / (1.0 + math.exp(-x))
        except OverflowError:
            return 1.0 if x > 0 else 0.0

    @staticmethod
    def _compute_confidence(evidence_count: int, profile_data: Dict[str, Any]) -> float:
        """Compute profile confidence based on evidence volume and source diversity."""
        sources = profile_data.get("sources", []) if isinstance(profile_data.get("sources"), list) else []
        num_sources = len(sources) if sources else len(profile_data.get("texts", [])) // 3

        # More evidence + more diverse sources = higher confidence
        evidence_factor = min(1.0, evidence_count / 15.0)
        source_factor = min(1.0, num_sources / 5.0)
        return round(0.2 + (evidence_factor * 0.5) + (source_factor * 0.3), 4)

    # ── Dict-style access for cached profiles ──

    def get_profile(self, name: str, org: str) -> Optional[Dict[str, Any]]:
        """Retrieve a previously computed profile."""
        key = f"{name}:{org}"
        profile = self._profiles.get(key)
        return profile.to_dict() if profile else None

    def list_profiles(self) -> List[str]:
        """List all cached profile keys."""
        return list(self._profiles.keys())

    def clear_cache(self) -> None:
        """Clear all cached profiles and writing analyses."""
        self._profiles.clear()
        self._writing_cache.clear()
        self._org_profiles.clear()
        logger.info("Psychological profiler cache cleared")
