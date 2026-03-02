from sqlalchemy import Column, Integer, String, Float
from backend.database import Base

class Spot(Base):
    __tablename__ = "spots"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    category = Column(String)
    city = Column(String)
    crowd_level = Column(Integer)
    lat = Column(Float)
    lon = Column(Float)