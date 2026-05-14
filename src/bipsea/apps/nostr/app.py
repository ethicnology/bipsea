from typing import Any

from bech32 import bech32_encode, convertbits

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.shared import hardened_int


def nsec_encode(key_bytes: bytes) -> str:
    data = convertbits(key_bytes, 8, 5)
    return bech32_encode("nsec", data)


class NostrApp:
    name = "nostr"
    code = "9000'"

    @property
    def params(self) -> list[Param]:
        return [
            Param(
                "identity",
                ("--identity",),
                int,
                required=True,
                range=(0, None),
                help="Identity index (0=proof/revocation key, >=1 usable).",
            ),
        ]

    def path_segments(self, index: int, identity: int, **_) -> list[str]:
        return [f"{identity}'", f"{index}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {
            "identity": hardened_int(segments[0]),
            "index": hardened_int(segments[1]),
        }

    def apply(self, entropy: bytes, **_) -> dict[str, Any]:
        key = entropy[:32]
        return {
            "entropy": key,
            "application": nsec_encode(key),
        }

    @property
    def vectors(self) -> list[TestVector]:
        return [
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/9000'/1'/1'",
                entropy="552ad1d578fe1bc927cec9612651652b07c52dde4017911bc23bc953568075ff",
                output="nsec1254dr4tclcdujf7we9sjv5t99vru2tw7gqtezx7z80y4x45qwhlsmxapst",
            ),
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/9000'/1'/2'",
                entropy="4fd36c0061a65db375b4350f44bb62a6d7f716ee93bd0f59887ac50b35fa8b96",
                output="nsec1flfkcqrp5ewmxad5x585fwmz5mtlw9hwjw7s7kvg0tzskd063wtq34wlgr",
            ),
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/9000'/2'/1'",
                entropy="b2d3b48992d46f98beac0196c4e258417087e467dbec1503342785368f4402c2",
                output="nsec1ktfmfzvj63he304vqxtvfcjcg9cg0er8m0kp2qe5y7zndr6yqtpq7q5y44",
            ),
        ]


app = NostrApp()
