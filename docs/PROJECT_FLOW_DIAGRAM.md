# shamir-ssh — conceptual flow (for slides and docs)

These diagrams explain **what** the system achieves and **how pieces relate**, not how the code is organized. Open in GitHub, VS Code (Mermaid preview), or [mermaid.live](https://mermaid.live) to export **PNG** / **SVG**.

---

## 1. The idea: from one fragile secret to k-of-n custody

```mermaid
flowchart LR
    subgraph Before["Typical situation"]
        K1[("Single private key\n(one file)")]
    end

    subgraph After["With Shamir sharing"]
        K2[("Logical secret:\nstill one key")]
        S1[Share 1]
        S2[Share 2]
        S3[Share 3]
        SD[...]
        SN[Share n]
    end

    K1 -->|"split (threshold k, total n)"| K2
    K2 --> S1 & S2 & S3 & SD & SN

    subgraph Rule["Recovery rule"]
        R["Any **k** shares together → full key\nFewer than **k** → no practical recovery"]
    end

    S1 & S2 & S3 -.-> R
```

**Message for an audience:** nobody needs to hold the whole key alone; compromise of fewer than *k* custodians does not reveal the key (under standard Shamir assumptions).

---

## 2. Threshold at a glance (k-of-n)

```mermaid
flowchart TB
    subgraph Custodians["n custodians (example)"]
        A[Alice — share A]
        B[Bob — share B]
        C[Carol — share C]
        D[Dana — share D]
        E[Evan — share E]
    end

    subgraph Enough["k = 3: these three can recover"]
        A
        B
        C
    end

    subgraph NotEnough["Any 2 shares: not enough"]
        X["…"]
    end

    A & B & C --> REC[Reconstruct private key]
    REC --> SSH[Use key — e.g. SSH login]

    style NotEnough fill:#f5f5f5,stroke-dasharray: 5 5
```

---

## 3. Why two layers: “protect the big blob, split the small key”

Conceptually the tool does **encrypt-then-share**:

```mermaid
flowchart LR
    PEM[("SSH private key\n(large, sensitive file)")]

    subgraph Protect["Protect the whole file"]
        SYM[("Random symmetric key\n(small)")]
        ENC[Authenticated encryption\nconfidentiality + integrity]
        BLOB[("One sealed blob\nsame on every share")]
    end

    subgraph Share["Share only the small secret"]
        SPLIT[Shamir threshold split\nk-of-n mathematical pieces]
        PIECES[("n share payloads\n— each useless alone")]
    end

    PEM --> ENC
    SYM --> ENC
    ENC --> BLOB
    SYM --> SPLIT
    SPLIT --> PIECES
    BLOB --> PIECES

    PIECES --> NOTE["Each custodian’s share carries:\n• their unique math piece\n• the same sealed blob\n→ need **k** pieces to unlock the blob"]
```

**Message:** Shamir applies to a **short** secret (the symmetric key); the **entire** key file is encrypted so one field element is enough and the design stays standard.

---

## 4. Lifecycle: split → distribute → (optional) central store → recover

```mermaid
flowchart TB
    START[("Operator has one\nSSH private key")]

    SPLIT_OP[Split into n shares\nset threshold k]
    START --> SPLIT_OP

    SPLIT_OP --> D1[Share to person / safe / region 1]
    SPLIT_OP --> D2[Share to person / safe / region 2]
    SPLIT_OP --> D3[Share to …]
    SPLIT_OP --> DN[Share n]

    subgraph Optional["Optional: operational convenience"]
        CLOUD[("Store consolidated copy\nin a cloud secret vault\ne.g. AWS Secrets Manager")]
    end

    D1 & D2 & D3 & DN -.->|"may upload"| CLOUD

    subgraph Recover["When SSH access is needed"]
        GATHER[Collect any k shares\nfrom files or vault]
        MERGE[Reconstruct key material]
        USE[SSH or write PEM once]
    end

    D1 & D2 & D3 -.->|"k shares"| GATHER
    CLOUD -->|"fetch + k implied\nin one blob"| GATHER
    GATHER --> MERGE --> USE
```

---

## 5. Two ways to use the recovered key

```mermaid
flowchart LR
    subgraph Paths["After reconstruction"]
        PEM[("Full private key\nin memory or file")]
    end

    PEM --> CLASSIC[Classic use:\nsave to file, run normal `ssh -i …`]
    PEM --> EPHEMERAL[Ephemeral use:\nload into short-lived agent,\nconnect, then discard from agent]

    EPHEMERAL --> BENEFIT["Key never written to disk\nfor that session\n(tradeoffs: RAM / agent still apply)"]
```

**Message:** the project supports **recovery to a file** or **one-shot SSH** where the key stays in memory for the session only.

---

## 6. Ephemeral SSH session (conceptual timeline)

```mermaid
sequenceDiagram
    participant U as Operator
    participant V as Secret vault / shares
    participant T as Tool
    participant M as Memory only
    participant A as SSH agent
    participant S as SSH client
    participant H as Remote host

    U->>T: Request login user@host
    T->>V: Fetch sealed material credentials permitting
    V-->>T: Encrypted bundle + share data
    T->>M: Reconstruct private key bytes
    M-->>T: Key never saved as a file
    T->>A: Load key into temporary agent
    T->>S: Start SSH using agent
    S->>H: Authenticate with public-key
    H-->>U: Shell / session
    Note over T,A: When session ends, tear down agent
```

---

## 7. Trust and scope (what this does / does not claim)

```mermaid
flowchart TB
    subgraph Provides["Designed to support"]
        P1[No single share reveals the key]
        P2[k-of-n recovery policy]
        P3[Optional: fewer places storing a full PEM]
        P4[Optional: SSH without writing PEM for that login]
    end

    subgraph DoesNot["Still responsibility of deployment"]
        N1[Who is allowed to fetch vault secrets IAM / policy]
        N2[Physical security of share holders]
        N3[Backup and versioning of secrets in the cloud]
        N4[Endpoint security RAM swap malware]
    end
```

---

## 8. One-slide summary

```mermaid
flowchart LR
    A[One SSH private key] --> B[Split k-of-n]
    B --> C[Distribute shares]
    C --> D{Need access?}
    D -->|yes| E[Gather k shares]
    E --> F[Reconstruct key]
    F --> G[SSH or save PEM]
    D -->|no| C
```

---

*For implementation details (modules, CLI flags, formats), see the project README.*
