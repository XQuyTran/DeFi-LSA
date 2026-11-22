D3.1 Event Decoding Engine
Objective

Biến:

raw logs
raw transactions
raw receipts
ABI


thành:

decoded events
decoded function calls


Đây là đầu vào cho toàn bộ D3.

Inputs
data/raw/normalized/logs/
data/raw/normalized/transactions/
data/raw/normalized/receipts/
abi/

Outputs
data/decoded/decoded_events.parquet

data/decoded/decoded_calls.parquet

Implementation Tasks
D3.1.1 ABI Resolver
resolve_contract_abi()
get_event_definition()
get_function_definition()


Acceptance:

100% scoped contracts have ABI

D3.1.2 Event Decoder
decode_log()
decode_topic0()


Decode:

Transfer
Deposit
Withdraw
Swap
Borrow
Repay

D3.1.3 Function Decoder
decode_input_data()


Decode:

deposit()
withdraw()
redeem()
supply()
flashLoan()

D3.1.4 Unknown Event Registry

Store:

event signature
contract
tx_hash


for anything not decodable.

Acceptance:

unknown_event_report.json exists

D3.2 Transaction & Flow Classification
Objective

Xác định transaction đó thực hiện hành động gì.

Outputs
classified_transactions.parquet

Labels
deposit
withdrawal
swap
liquidation
flash_loan
exploit
recovery
unknown

Tasks
D3.2.1 Rule Engine
classify_transaction()


Priority rules:

exploit
recovery
flash loan
withdrawal
deposit
swap

D3.2.2 Exploit Mapping

Map:

Euler exploit txs

Kyber exploit txs


using registry anchors.

D3.2.3 Quality Audit

Compute:

unknown_flow_share


Acceptance:

≤ 5%

D3.3 Actor Attribution Engine
Objective

Gán vai trò cho dòng tiền.

Outputs
actor_roles.parquet

Labels
attacker

whitehat

user

protocol

unknown

Tasks
D3.3.1 Entity Loader

Load:

entities.json
incident_legs.json

D3.3.2 Address Attribution
classify_actor()

D3.3.3 Transaction Attribution

Produce:

tx_hash
actor_role
confidence
evidence


Acceptance

100% exploit txs attributed

D3.4 Incident Leg Reconstruction
Objective

Liên kết:

event
pool
token
actor
transaction

Outputs
incident_legs_resolved.parquet

Tasks
D3.4.1 Pool Mapping

Euler:

asset legs


Kyber:

affected pool

D3.4.2 Relationship Graph

Build:

event
 -> pool
 -> tx
 -> actor
 -> token


Acceptance

Every registered exploit tx
belongs to exactly one incident leg

D3.5 Dataset Readiness for D4
Objective

Chuẩn bị dữ liệu để D4 tính:

UserNetOutflow
AttackerFlow
Liquidity

Outputs
decoded_events.parquet

classified_transactions.parquet

actor_roles.parquet

balance_inputs.parquet

Tasks
D3.5.1 Decoding Coverage Report
{
  "decoded_value_pct": ...
}


Acceptance:

>=95%

D3.5.2 Classification Coverage Report

Acceptance:

unknown_flow_share <=5%

D3.5.3 D3 Gate Report

Output:

reports/d3_gate_report.json


Status:

GO
CONDITIONAL_GO
NO_GO

