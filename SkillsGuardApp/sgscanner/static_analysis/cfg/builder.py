import ast
import logging
from typing import Any, Generic, TypeVar
from ..parser.python_parser import PythonParser
T = TypeVar('T')

class CFGNode:

    def __init__(self, node_id: int, ast_node: Any, label: str='') -> None:
        self.id = node_id
        self.ast_node = ast_node
        self.label = label
        self.predecessors: list[CFGNode] = []
        self.successors: list[CFGNode] = []

    def __repr__(self) -> str:
        return f'CFGNode({self.id}, {self.label})'

class ControlFlowGraph:

    def __init__(self) -> None:
        self.nodes: list[CFGNode] = []
        self.entry: CFGNode | None = None
        self.exit: CFGNode | None = None
        self._node_counter = 0

    def create_node(self, ast_node: Any, label: str='') -> CFGNode:
        node = CFGNode(self._node_counter, ast_node, label)
        self._node_counter += 1
        self.nodes.append(node)
        return node

    def add_edge(self, from_node: CFGNode, to_node: CFGNode) -> None:
        from_node.successors.append(to_node)
        to_node.predecessors.append(from_node)

    def get_successors(self, node: CFGNode) -> list[CFGNode]:
        return node.successors

    def get_predecessors(self, node: CFGNode) -> list[CFGNode]:
        return node.predecessors

class DataFlowAnalyzer(Generic[T]):

    def __init__(self, parser: PythonParser) -> None:
        self.parser = parser
        self.cfg: ControlFlowGraph | None = None
        self.in_facts: dict[int, T] = {}
        self.out_facts: dict[int, T] = {}
        self.logger = logging.getLogger('sg.' + __name__)

    def build_cfg(self) -> ControlFlowGraph:
        ast_root = getattr(self.parser, 'tree', None)
        if not ast_root:
            self.logger.warning('Cannot build CFG: no AST available. Call parser.parse() first.')
            return ControlFlowGraph()
        self.in_facts.clear()
        self.out_facts.clear()
        cfg = ControlFlowGraph()
        self._build_python_cfg(ast_root, cfg)
        self.cfg = cfg
        return cfg

    def _build_python_cfg(self, node: ast.AST, cfg: ControlFlowGraph) -> CFGNode:
        if isinstance(node, ast.Module):
            entry = cfg.create_node(node, 'entry')
            cfg.entry = entry
            current = entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(current, next_node)
                current = next_node
            exit_node = cfg.create_node(node, 'exit')
            cfg.exit = exit_node
            cfg.add_edge(current, exit_node)
            return exit_node
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            entry = cfg.create_node(node, 'func_entry')
            if not cfg.entry:
                cfg.entry = entry
            current = entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(current, next_node)
                current = next_node
            exit_node = cfg.create_node(node, 'func_exit')
            if not cfg.exit:
                cfg.exit = exit_node
            cfg.add_edge(current, exit_node)
            return exit_node
        elif isinstance(node, ast.If):
            cond_node = cfg.create_node(node.test, 'if_cond')
            then_entry = cfg.create_node(node, 'then_entry')
            cfg.add_edge(cond_node, then_entry)
            then_current = then_entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(then_current, next_node)
                then_current = next_node
            if node.orelse:
                else_entry = cfg.create_node(node, 'else_entry')
                cfg.add_edge(cond_node, else_entry)
                else_current = else_entry
                for stmt in node.orelse:
                    next_node = self._build_python_cfg(stmt, cfg)
                    cfg.add_edge(else_current, next_node)
                    else_current = next_node
                merge = cfg.create_node(node, 'if_merge')
                cfg.add_edge(then_current, merge)
                cfg.add_edge(else_current, merge)
                return merge
            else:
                merge = cfg.create_node(node, 'if_merge')
                cfg.add_edge(then_current, merge)
                cfg.add_edge(cond_node, merge)
                return merge
        elif isinstance(node, ast.While):
            cond_node = cfg.create_node(node.test, 'while_cond')
            body_entry = cfg.create_node(node, 'while_body')
            cfg.add_edge(cond_node, body_entry)
            body_current = body_entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(body_current, next_node)
                body_current = next_node
            cfg.add_edge(body_current, cond_node)
            exit_node = cfg.create_node(node, 'while_exit')
            cfg.add_edge(cond_node, exit_node)
            return exit_node
        elif isinstance(node, ast.For):
            iter_node = cfg.create_node(node.iter, 'for_iter')
            body_entry = cfg.create_node(node, 'for_body')
            cfg.add_edge(iter_node, body_entry)
            body_current = body_entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(body_current, next_node)
                body_current = next_node
            cfg.add_edge(body_current, iter_node)
            exit_node = cfg.create_node(node, 'for_exit')
            cfg.add_edge(iter_node, exit_node)
            return exit_node
        elif isinstance(node, ast.Try):
            try_entry = cfg.create_node(node, 'try_entry')
            current = try_entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(current, next_node)
                current = next_node
            if node.handlers:
                for handler in node.handlers:
                    handler_entry = cfg.create_node(handler, 'except_entry')
                    cfg.add_edge(try_entry, handler_entry)
                    handler_current = handler_entry
                    for stmt in handler.body:
                        next_node = self._build_python_cfg(stmt, cfg)
                        cfg.add_edge(handler_current, next_node)
                        handler_current = next_node
                    cfg.add_edge(handler_current, current)
            if node.finalbody:
                finally_entry = cfg.create_node(node, 'finally_entry')
                cfg.add_edge(current, finally_entry)
                finally_current = finally_entry
                for stmt in node.finalbody:
                    next_node = self._build_python_cfg(stmt, cfg)
                    cfg.add_edge(finally_current, next_node)
                    finally_current = next_node
                return finally_current
            return current
        else:
            return cfg.create_node(node, type(node).__name__)

    def run(self, initial_fact: T, forward: bool=True, max_iteration_multiplier: int=1000) -> None:
        if not self.cfg:
            self.build_cfg()
        if not self.cfg or not self.cfg.nodes:
            return
        self.in_facts.clear()
        self.out_facts.clear()
        for node in self.cfg.nodes:
            self.in_facts[node.id] = initial_fact
            self.out_facts[node.id] = initial_fact
        worklist = list(self.cfg.nodes)
        in_worklist = {node.id for node in worklist}
        iteration_count = 0
        cfg_size = len(self.cfg.nodes)
        if cfg_size < 20:
            effective_multiplier = max_iteration_multiplier
        elif cfg_size < 50:
            effective_multiplier = int(max_iteration_multiplier * 0.8)
        elif cfg_size < 100:
            effective_multiplier = int(max_iteration_multiplier * 0.6)
        elif cfg_size < 200:
            effective_multiplier = int(max_iteration_multiplier * 0.4)
        else:
            effective_multiplier = int(max_iteration_multiplier * 0.3)
        max_iterations = cfg_size * effective_multiplier
        while worklist:
            iteration_count += 1
            if iteration_count > max_iterations:
                self.logger.debug(f'Dataflow analysis exceeded max iterations ({max_iterations:,} iterations, CFG size: {cfg_size} nodes). Analysis stopped at safety limit. This is normal for complex control flow and analysis may be incomplete.')
                break
            node = worklist.pop(0)
            in_worklist.discard(node.id)
            if forward:
                pred_facts = [self.out_facts[pred.id] for pred in node.predecessors]
                if pred_facts:
                    in_fact = self.merge(pred_facts)
                else:
                    in_fact = initial_fact
                self.in_facts[node.id] = in_fact
                out_fact = self.transfer(node, in_fact)
                if out_fact != self.out_facts[node.id]:
                    self.out_facts[node.id] = out_fact
                    for succ in node.successors:
                        if succ.id not in in_worklist:
                            worklist.append(succ)
                            in_worklist.add(succ.id)
            else:
                succ_facts = [self.in_facts[succ.id] for succ in node.successors]
                if succ_facts:
                    out_fact = self.merge(succ_facts)
                else:
                    out_fact = initial_fact
                self.out_facts[node.id] = out_fact
                in_fact = self.transfer(node, out_fact)
                if in_fact != self.in_facts[node.id]:
                    self.in_facts[node.id] = in_fact
                    for pred in node.predecessors:
                        if pred.id not in in_worklist:
                            worklist.append(pred)
                            in_worklist.add(pred.id)

    def transfer(self, node: CFGNode, in_fact: T) -> T:
        return in_fact

    def merge(self, facts: list[T]) -> T:
        if facts:
            return facts[0]
        raise NotImplementedError('merge must be implemented by subclass')

    def get_reaching_definitions(self, node: CFGNode) -> T:
        return self.in_facts.get(node.id, self.in_facts.get(0) if self.in_facts else None)
