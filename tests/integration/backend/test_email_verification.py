import pytest
from backend.src.auth import verification
from backend.src.auth import service as auth
from backend.src.tenants import service as tenants


@pytest.mark.asyncio
async def test_issue_and_consume(db_session):
    t = await tenants.create_tenant(db_session, name="acme01", display_name="Acme")
    u = await auth.create_client_user(
        db_session, email="a@b.com", password="hunter22a", tenant_id=t.id
    )
    token = await verification.issue(db_session, u, purpose="verify_email")
    assert isinstance(token, str)
    assert len(token) > 20

    user_back = await verification.consume(db_session, token, purpose="verify_email")
    assert user_back is not None
    assert user_back.id == u.id

    # Second consume fails (one-shot)
    assert await verification.consume(db_session, token, purpose="verify_email") is None


@pytest.mark.asyncio
async def test_wrong_purpose_rejected(db_session):
    t = await tenants.create_tenant(db_session, name="acme02", display_name="Acme2")
    u = await auth.create_client_user(
        db_session, email="b@b.com", password="hunter22b", tenant_id=t.id
    )
    token = await verification.issue(db_session, u, purpose="verify_email")
    # Consuming with wrong purpose returns None
    assert await verification.consume(db_session, token, purpose="reset_password") is None


@pytest.mark.asyncio
async def test_reset_password_token(db_session):
    t = await tenants.create_tenant(db_session, name="acme03", display_name="Acme3")
    u = await auth.create_client_user(
        db_session, email="c@b.com", password="hunter22c", tenant_id=t.id
    )
    token = await verification.issue(db_session, u, purpose="reset_password")
    user_back = await verification.consume(db_session, token, purpose="reset_password")
    assert user_back is not None
    assert user_back.id == u.id
