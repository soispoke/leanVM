"""Compile a generator written in a Python subset to the bytecode decode.py runs.

The subset: top-level functions (no recursion: a function may call only functions defined above it), `for x in
range(...)` / `for x in list`, if/elif/else, break, return, assignment (names, subscripts, tuple unpacking), int and
list and dict values, list comprehensions with one `for`, and the builtins len, row, N, dict, min, max, list, abs.
Python itself runs the same source (with `row`/`N` defined) for fast checking: the semantics coincide.
"""
import ast, sys

LIT, VAR, SET, LIST, FOR, IF, DEF, CALL, RET, BRK, AND, OR, VEC = range(13)
ADD, SUB, MUL, FDIV, MOD, BAND, BOR, BXOR, SHL, SHR, EQ, NE, LT, LE, NEG, NOT, GET, SLICE, SETITEM, LEN, APPEND, \
    POP, CONTAINS, DICT, MGET, ROW, COUNT = range(13, 40)
BIN = {ast.Add: ADD, ast.Sub: SUB, ast.Mult: MUL, ast.FloorDiv: FDIV, ast.Mod: MOD, ast.BitAnd: BAND,
       ast.BitOr: BOR, ast.BitXor: BXOR, ast.LShift: SHL, ast.RShift: SHR}
CMP = {ast.Eq: (EQ, False), ast.NotEq: (NE, False), ast.Lt: (LT, False), ast.LtE: (LE, False), ast.Gt: (LT, True),
       ast.GtE: (LE, True)}
BIG = 1 << 40


def varint(v):
    assert v >= 0
    out = bytearray()
    while v > 127:
        out.append(v & 127 | 128)
        v >>= 7
    out.append(v)
    return bytes(out)


class Compiler:
    def __init__(self):
        self.slots = {}          # (scope, name) -> slot
        self.funcs = {}          # name -> (id, param slots)
        self.scope = None
        self.locals = set()
        self.globals_decl = set()
        self.tmp = 0
        self.slot(None, "PUBLIC")  # slot 0: the public sources

    def slot(self, scope, name):
        key = (scope, name)
        if key not in self.slots:
            self.slots[key] = len(self.slots)
        return self.slots[key]

    def var(self, name):
        if self.scope is not None and name in self.locals and name not in self.globals_decl:
            return self.slot(self.scope, name)
        return self.slot(None, name)

    def fresh(self):
        self.tmp += 1
        return self.slot(self.scope, f"$t{self.tmp}")

    def node(self, op, *args):
        out = varint(op)
        for a in args:
            out += varint(a) if isinstance(a, int) else a
        return out

    def lit(self, v):
        v = int(v)
        return self.node(LIT, v) if v >= 0 else self.node(NEG, self.node(LIT, -v))

    def seq(self, parts):
        return self.node(LIST, len(parts), *parts)

    # ---------------- expressions
    def expr(self, e):
        t = type(e)
        if t is ast.Constant:
            assert isinstance(e.value, (int, bool)), e.value
            return self.lit(e.value)
        if t is ast.Name:
            if e.id in ("True", "False"):
                return self.lit(e.id == "True")
            return self.node(VAR, self.var(e.id))
        if t is ast.BinOp:
            return self.node(BIN[type(e.op)], self.expr(e.left), self.expr(e.right))
        if t is ast.UnaryOp:
            if isinstance(e.op, ast.USub):
                if isinstance(e.operand, ast.Constant):
                    return self.lit(-e.operand.value)
                return self.node(NEG, self.expr(e.operand))
            if isinstance(e.op, ast.Not):
                return self.node(NOT, self.expr(e.operand))
            if isinstance(e.op, ast.Invert):
                return self.node(SUB, self.node(NEG, self.expr(e.operand)), self.lit(1))
            raise SyntaxError(ast.dump(e))
        if t is ast.BoolOp:
            op = AND if isinstance(e.op, ast.And) else OR
            out = self.expr(e.values[-1])
            for v in reversed(e.values[:-1]):
                out = self.node(op, self.expr(v), out)
            return out
        if t is ast.Compare:
            assert len(e.ops) == 1, ast.dump(e)
            a, b, op = e.left, e.comparators[0], type(e.ops[0])
            if op in (ast.In, ast.NotIn):
                r = self.node(CONTAINS, self.expr(b), self.expr(a))
                return self.node(NOT, r) if op is ast.NotIn else r
            if op in (ast.Is, ast.IsNot):
                raise SyntaxError("is")
            code, swap = CMP[op]
            return self.node(code, *( (self.expr(b), self.expr(a)) if swap else (self.expr(a), self.expr(b))))
        if t is ast.IfExp:
            return self.node(IF, self.expr(e.test), self.expr(e.body), self.expr(e.orelse))
        if t is ast.Subscript:
            if isinstance(e.slice, ast.Slice):
                s = e.slice
                assert s.step is None
                lo = self.expr(s.lower) if s.lower else self.lit(0)
                hi = self.expr(s.upper) if s.upper else self.lit(BIG)
                return self.node(SLICE, self.expr(e.value), lo, hi)
            return self.node(GET, self.expr(e.value), self.expr(e.slice))
        if t in (ast.List, ast.Tuple):
            return self.seq([self.expr(x) for x in e.elts])
        if t is ast.Dict:
            assert not e.keys
            return self.node(DICT)
        if t is ast.ListComp:
            assert len(e.generators) == 1 and not e.generators[0].ifs
            g = e.generators[0]
            assert isinstance(g.target, ast.Name)
            s = self.var(g.target.id)
            n, pre = self.range_of(g.iter, s)
            if pre is None:
                return self.node(VEC, s, n, self.expr(e.elt))
            # over a list: pre is (temp slot of list, counter slot)
            lst, k = pre
            body = self.node(GET, self.seq([self.node(SET, s, self.node(GET, self.node(VAR, lst), self.node(VAR, k))),
                                            self.expr(e.elt)]), self.lit(1))
            return self.node(
                GET, self.seq([self.node(SET, lst, n), self.node(VEC, k, self.node(LEN, self.node(VAR, lst)), body)]),
                self.lit(1))
        if t is ast.Call:
            return self.call(e)
        raise SyntaxError(ast.dump(e))

    def range_of(self, it, s):
        """For `for s in it`: (count expr, None) for a range from 0, or (list expr, (list slot, counter slot))."""
        if isinstance(it, ast.Call) and isinstance(it.func, ast.Name) and it.func.id == "range":
            assert len(it.args) == 1, "range(a, b) is only supported in for statements"
            return self.expr(it.args[0]), None
        return self.expr(it), (self.fresh(), self.fresh())

    def call(self, e):
        f = e.func
        args = e.args
        if isinstance(f, ast.Attribute):
            obj = self.expr(f.value)
            m = f.attr
            if m == "append":
                return self.node(APPEND, obj, self.expr(args[0]))
            if m == "pop":
                return self.node(POP, obj, self.expr(args[0]) if args else self.node(NEG, self.lit(1)))
            if m == "get":
                return self.node(MGET, obj, self.expr(args[0]), self.expr(args[1]))
            if m == "copy":
                return self.node(SLICE, obj, self.lit(0), self.lit(BIG))
            raise SyntaxError(m)
        name = f.id
        if name in self.funcs:
            fid, params = self.funcs[name]
            assert len(args) == len(params), name
            return self.node(CALL, fid, *[self.expr(a) for a in args])
        if name == "len":
            return self.node(LEN, self.expr(args[0]))
        if name == "row":
            return self.node(ROW, *[self.expr(a) for a in args])
        if name == "N":
            return self.node(COUNT)
        if name == "dict":
            return self.node(DICT)
        if name == "list":
            return self.node(SLICE, self.expr(args[0]), self.lit(0), self.lit(BIG))
        if name in ("min", "max"):
            a, b = args
            # pure operands only (evaluated twice)
            cmp = self.node(LT, self.expr(a), self.expr(b))
            return self.node(IF, cmp, *((self.expr(a), self.expr(b)) if name == "min" else (self.expr(b), self.expr(a))))
        if name == "abs":
            x = args[0]
            return self.node(IF, self.node(LT, self.expr(x), self.lit(0)), self.node(NEG, self.expr(x)), self.expr(x))
        raise SyntaxError(f"unknown function {name}")

    # ---------------- statements
    def assign(self, target, value_code):
        if isinstance(target, ast.Name):
            return self.node(SET, self.var(target.id), value_code)
        if isinstance(target, ast.Subscript):
            assert not isinstance(target.slice, ast.Slice)
            return self.node(SETITEM, self.expr(target.value), self.expr(target.slice), value_code)
        if isinstance(target, (ast.Tuple, ast.List)):
            t = self.fresh()
            parts = [self.node(SET, t, value_code)]
            for i, el in enumerate(target.elts):
                parts.append(self.assign(el, self.node(GET, self.node(VAR, t), self.lit(i))))
            return self.seq(parts)
        raise SyntaxError(ast.dump(target))

    def stmts(self, body):
        parts = [self.stmt(s) for s in body]
        parts = [p for p in parts if p is not None]
        return parts[0] if len(parts) == 1 else self.seq(parts)

    def stmt(self, s):
        t = type(s)
        if t is ast.Expr:
            if isinstance(s.value, ast.Constant):
                return None  # docstring
            return self.expr(s.value)
        if t is ast.Assign:
            assert len(s.targets) == 1
            return self.assign(s.targets[0], self.expr(s.value))
        if t is ast.AugAssign:
            tg = s.target
            load = ast.Name(tg.id, ast.Load()) if isinstance(tg, ast.Name) else ast.Subscript(tg.value, tg.slice,
                                                                                               ast.Load())
            return self.assign(tg, self.node(BIN[type(s.op)], self.expr(load), self.expr(s.value)))
        if t is ast.For:
            assert not s.orelse
            it = s.iter
            if (isinstance(s.target, ast.Name) and isinstance(it, ast.Call) and isinstance(it.func, ast.Name)
                    and it.func.id == "range" and len(it.args) == 2):
                # for x in range(a, b): lo = a; for k in range(b - lo): x = lo + k
                sl, lo, k = self.var(s.target.id), self.fresh(), self.fresh()
                body = self.seq([self.node(SET, sl, self.node(ADD, self.node(VAR, lo), self.node(VAR, k))),
                                 self.stmts(s.body)])
                n = self.node(SUB, self.expr(it.args[1]), self.node(VAR, lo))
                return self.seq([self.node(SET, lo, self.expr(it.args[0])), self.node(FOR, k, n, body)])
            if isinstance(s.target, ast.Name):
                sl = self.var(s.target.id)
                n, pre = self.range_of(s.iter, sl)
                if pre is None:
                    return self.node(FOR, sl, n, self.stmts(s.body))
                lst, k = pre
                body = self.seq([self.node(SET, sl, self.node(GET, self.node(VAR, lst), self.node(VAR, k))),
                                 self.stmts(s.body)])
                return self.seq([self.node(SET, lst, n), self.node(FOR, k, self.node(LEN, self.node(VAR, lst)), body)])
            raise SyntaxError("for target")
        if t is ast.If:
            return self.node(IF, self.expr(s.test), self.stmts(s.body),
                             self.stmts(s.orelse) if s.orelse else self.seq([]))
        if t is ast.Return:
            return self.node(RET, self.expr(s.value) if s.value is not None else self.lit(0))
        if t is ast.Break:
            return self.node(BRK)
        if t is ast.Pass:
            return None
        if t is ast.Global:
            self.globals_decl |= set(s.names)
            return None
        if t is ast.Assert:
            return None
        if t is ast.FunctionDef:
            assert self.scope is None, "nested function"
            self.scope = s.name
            self.globals_decl = set()
            self.locals = {a.arg for a in s.args.args}
            for n in ast.walk(s):
                if isinstance(n, ast.Global):
                    self.globals_decl |= set(n.names)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    self.locals.add(n.id)
                if isinstance(n, ast.comprehension) and isinstance(n.target, ast.Name):
                    self.locals.add(n.target.id)
            params = [self.slot(s.name, a.arg) for a in s.args.args]
            body = self.stmts(s.body) if s.body else self.seq([])
            self.scope = None
            self.globals_decl = set()
            code = self.node(DEF, len(params), *params, body)
            self.funcs[s.name] = (len(self.funcs), params)
            return code
        if t in (ast.Import, ast.ImportFrom):
            return None
        raise SyntaxError(ast.dump(s))

    def program(self, src, log_rows):
        tree = ast.parse(src)
        body = self.stmts(tree.body)
        return varint(log_rows) + varint(len(self.slots)) + body


def compile_source(src, log_rows):
    return Compiler().program(src, log_rows)


if __name__ == "__main__":
    srcs = sys.argv[3:]
    src = "\n".join(open(f).read() for f in srcs)
    out = compile_source(src, int(sys.argv[2]))
    open(sys.argv[1], "wb").write(out)
    print(len(out), "bytes")
