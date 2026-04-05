from typing import Any

from bech32 import bech32_encode, convertbits

from bipsea.app_protocol import Param, TestVector
from bipsea.apps.shared import hardened_int


def nsec_encode(key_bytes: bytes) -> str:
    data = convertbits(key_bytes, 8, 5)
    return bech32_encode("nsec", data)


class NostrApp:
    name = "nostr"
    code = "86'"

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
            Param(
                "account",
                ("--account",),
                int,
                required=True,
                range=(0, None),
                help="Account index (0=proof key, >=1 usable).",
            ),
        ]

    def path_segments(self, index: int, identity: int, account: int, **_) -> list[str]:
        return [f"{identity}'", f"{account}'"]

    def parse_path(self, segments: list[str]) -> dict[str, Any]:
        return {
            "identity": hardened_int(segments[0]),
            "account": hardened_int(segments[1]),
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
                path="m/83696968'/86'/1'/1'",
                entropy="7f3313b1bdeacc4f395c666b473982550cdc66c225fd7e7b0f5d11d33cddde31",
                output="nsec10ue38vdaatxy7w2uve45wwvz25xdcekzyh7hu7c0t5gax0xamccsyuyesn",
            ),
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/86'/1'/2'",
                entropy="41fbfba9227f7d261ccb90f61264fd0b38e1f762108c31135f8fc138329594ff",
                output="nsec1g8alh2fz0a7jv8xtjrmpye8apvuwramzzzxrzy6l3lqnsv54jnlsuxjsql",
            ),
            TestVector(
                master="xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb",
                path="m/83696968'/86'/2'/1'",
                entropy="a159a41860a18457855511334a3c813430468ec3c1ef17700d4917d0e881a45a",
                output="nsec159v6gxrq5xz90p24zye550ypxscydrkrc8h3wuqdfytap6yp53dq5gdpd6",
            ),
        ]


app = NostrApp()
