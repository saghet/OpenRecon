from app.core.database import Base, engine
import app.models.domain_intel  # noqa: F401


def init_domain_intel_tables() -> None:
    """Crea las tablas del módulo Domain Intelligence si no existen."""
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_domain_intel_tables()
