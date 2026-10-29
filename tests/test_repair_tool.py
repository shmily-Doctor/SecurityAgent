
import repair_tool


# ==========================================
# 1. 测试夹具
# ==========================================

NEW_CODE = """\
password = "demo"
"""


def make_lab(tmp_path, name="demo.py", body='password = "123456"\n'):
    lab = tmp_path / "security_lab"
    lab.mkdir()
    target = lab / name
    target.write_text(body, encoding="utf-8")
    return lab, target


def patch_lab(monkeypatch, lab):
    monkeypatch.setattr(repair_tool, "SCAN_DIR", lab.resolve())


def backups(lab):
    return sorted(lab.glob("*.bak"))


# ==========================================
# 2. 入参校验：只读不写
# ==========================================

def test_rejects_directory_path(tmp_path, monkeypatch):
    lab, _ = make_lab(tmp_path)
    patch_lab(monkeypatch, lab)

    result = repair_tool.propose_code_fix_impl(
        "sub/demo.py", NEW_CODE, approve=lambda diff: True
    )

    assert result.startswith("拒绝")
    assert not backups(lab)


def test_rejects_non_python_file(tmp_path, monkeypatch):
    lab, _ = make_lab(tmp_path, name="demo.txt")
    patch_lab(monkeypatch, lab)

    result = repair_tool.propose_code_fix_impl(
        "demo.txt", NEW_CODE, approve=lambda diff: True
    )

    assert result.startswith("拒绝")


def test_rejects_missing_file(tmp_path, monkeypatch):
    lab, _ = make_lab(tmp_path)
    patch_lab(monkeypatch, lab)

    result = repair_tool.propose_code_fix_impl(
        "absent.py", NEW_CODE, approve=lambda diff: True
    )

    assert result.startswith("拒绝")


def test_rejects_path_escape(tmp_path, monkeypatch):
    lab, _ = make_lab(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("x = 1\n", encoding="utf-8")

    # 校验逻辑用 resolve() 判断，这里直接调用底层函数验证
    patch_lab(monkeypatch, lab)

    try:
        repair_tool.build_fix_plan("../outside.py", NEW_CODE)
    except repair_tool.FixRejected:
        pass
    else:
        raise AssertionError("父目录穿越未被拒绝")


# ==========================================
# 3. 差异生成
# ==========================================

def test_build_plan_returns_diff(tmp_path, monkeypatch):
    lab, target = make_lab(tmp_path)
    patch_lab(monkeypatch, lab)

    plan = repair_tool.build_fix_plan("demo.py", NEW_CODE)

    assert plan["target"] == target.resolve()
    assert "-password" in plan["diff"]
    assert "+password" in plan["diff"]
    # 只读：生成方案不落盘
    assert target.read_text(encoding="utf-8") == 'password = "123456"\n'
    assert not backups(lab)


# ==========================================
# 4. 审批与原子写入
# ==========================================

def test_unapproved_change_leaves_file_intact(tmp_path, monkeypatch):
    lab, target = make_lab(tmp_path)
    patch_lab(monkeypatch, lab)

    result = repair_tool.propose_code_fix_impl(
        "demo.py", NEW_CODE, approve=lambda diff: False
    )

    assert "未批准" in result
    assert target.read_text(encoding="utf-8") == 'password = "123456"\n'
    assert not backups(lab)


def test_approved_change_writes_and_backs_up(tmp_path, monkeypatch):
    lab, target = make_lab(tmp_path)
    patch_lab(monkeypatch, lab)

    seen = {}

    def approve(diff):
        seen["diff"] = diff
        return True

    result = repair_tool.propose_code_fix_impl(
        "demo.py", NEW_CODE, approve=approve
    )

    assert "修改成功" in result
    assert "password" in seen["diff"]

    # 新内容写入，旧内容留在备份里
    assert target.read_text(encoding="utf-8") == NEW_CODE

    saved = backups(lab)
    assert len(saved) == 1
    assert saved[0].read_text(encoding="utf-8") == 'password = "123456"\n'

    # 临时文件不得残留
    assert not list(lab.glob("*.tmp"))
    assert not list(lab.glob(".*.tmp"))


def test_identical_code_reports_no_change(tmp_path, monkeypatch):
    lab, target = make_lab(tmp_path)
    patch_lab(monkeypatch, lab)

    result = repair_tool.propose_code_fix_impl(
        "demo.py", 'password = "123456"\n', approve=lambda diff: True
    )

    assert "没有检测到代码变化" in result
    assert not backups(lab)


def test_write_failure_keeps_original(tmp_path, monkeypatch):
    lab, target = make_lab(tmp_path)
    patch_lab(monkeypatch, lab)

    real_copy = repair_tool.shutil.copy2

    def boom(source, destination):
        raise OSError("disk full")

    monkeypatch.setattr(repair_tool.shutil, "copy2", boom)

    result = repair_tool.propose_code_fix_impl(
        "demo.py", NEW_CODE, approve=lambda diff: True
    )

    monkeypatch.setattr(repair_tool.shutil, "copy2", real_copy)

    assert "写入失败" in result
    assert target.read_text(encoding="utf-8") == 'password = "123456"\n'
    assert not list(lab.glob("*.tmp"))


def test_change_during_approval_is_not_overwritten(tmp_path, monkeypatch):
    lab, target = make_lab(tmp_path)
    patch_lab(monkeypatch, lab)

    def approve(diff):
        target.write_text("changed = True\n", encoding="utf-8")
        return True

    result = repair_tool.propose_code_fix_impl("demo.py", NEW_CODE, approve=approve)
    assert "发生变化" in result
    assert target.read_text(encoding="utf-8") == "changed = True\n"
    assert not backups(lab)


def test_rejects_source_too_long_for_model(tmp_path, monkeypatch):
    lab, target = make_lab(tmp_path, body="x = 1\n" * 4000)
    patch_lab(monkeypatch, lab)
    result = repair_tool.propose_code_fix_impl("demo.py", NEW_CODE, approve=lambda diff: True)
    assert "无法基于完整源码修复" in result
    assert target.read_text(encoding="utf-8") == "x = 1\n" * 4000
