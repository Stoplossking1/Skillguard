from dataclasses import dataclass

@dataclass
class Position:
    line: int
    column: int
    offset: int

@dataclass
class Range:
    start: Position
    end: Position
