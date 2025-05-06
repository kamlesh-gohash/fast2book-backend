from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from beanie import Document, Link
from pydantic import BaseModel, Field

from app.v1.models.services import Service
from app.v1.models.user import Location, StatusEnum, User


class BusinessType(str, Enum):
    individual = "individual"
    business = "business"


class TimeSlot(BaseModel):
    start_time: str
    end_time: str
    max_seat: int = Field(..., gt=0, description="Maximum number of seats for the time slot")
    duration: int = Field(default=0, description="Duration of the time slot in minutes")

    def calculate_duration(self):
        """
        Calculate the duration between start_time and end_time in minutes.
        """
        try:
            start = datetime.strptime(self.start_time, "%H:%M")
            end = datetime.strptime(self.end_time, "%H:%M")
            self.duration = int((end - start).total_seconds() / 60)
        except Exception as e:
            raise ValueError(f"Error calculating duration: {str(e)}")


class DaySlot(BaseModel):
    day: str
    time_slots: List[TimeSlot]


# class Service(BaseModel):
#     id: str
#     name: Optional[str] = None


class BillingAddress(Document):
    address_line_1: Optional[str] = Field(None, max_length=255, description="First line of the billing address")
    address_line_2: Optional[str] = Field(None, max_length=255, description="Second line of the billing address")
    city: Optional[str] = Field(None, max_length=100, description="City of the billing address")
    state_province: Optional[str] = Field(None, max_length=100, description="State or province of the billing address")
    postcode: Optional[str] = Field(None, max_length=20, description="Postcode of the billing address")
    country: Optional[str] = Field(None, max_length=100, description="Country of the billing address")


class Vendor(Document):
    # vendor_images: Optional[List[str]] = Field(None, description="Array of vendor image URLs")
    vendor_image: Optional[str] = None
    image_url: Optional[str] = None
    business_name: str = Field(..., min_length=1, max_length=50)
    # user_id: Link[User]
    business_type: BusinessType = Field(default=BusinessType.individual)
    business_name: Optional[str] = Field(None, max_length=100)
    business_address: Optional[str] = Field(None, max_length=255)
    business_details: Optional[str] = None
    billing_address: Optional[BillingAddress] = Field(None, description="Structured billing address of the vendor")
    category_id: Optional[str] = Field(None, description="ID of the selected category")
    category_name: Optional[str] = Field(None, description="Name of the selected category")
    services: Optional[List[Service]] = Field(None, description="List of selected services with their IDs and names")
    service_details: Optional[str] = None
    status: StatusEnum = Field(default=StatusEnum.Active)
    # availability_slots: Optional[Link["SlotRequest"]] = None
    fees: float = Field(default=0.0)
    location: Optional[Location] = Field(None, description="Location details of the vendor")
    razorpay_customer_id: Optional[str] = None
    razorpay_account_id: Optional[str] = None
    is_subscription: bool = Field(default=False)
    is_payment_required: bool = Field(default=False)
    vendor_account_data: Optional[List[Dict]] = None  # New field for array storage
    vendor_services_image: Optional[List[str]] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Settings:
        name = "vendors"


BUSINESS_CATEGORIES = [
    "financial_services",
    "education",
    "healthcare",
    "utilities",
    "government",
    "logistics",
    "tours_and_travel",
    "transport",
    "ecommerce",
    "food",
    "it_and_software",
    "gaming",
    "media_and_entertainment",
    "services",
    "housing",
    "not_for_profit",
    "social",
    "others",
]

BUSINESS_SUB_CATEGORIES = {
    "financial_services": [
        "mutual_fund",
        "lending",
        "cryptocurrency",
        "insurance",
        "nbfc",
        "cooperatives",
        "pension_fund",
        "forex",
        "securities",
        "commodities",
        "accounting",
        "financial_advisor",
        "crowdfunding",
        "trading",
        "betting",
        "get_rich_schemes",
        "moneysend_funding",
        "wire_transfers_and_money_orders",
        "tax_preparation_services",
        "tax_payments",
        "digital_goods",
        "atms",
    ],
    "education": [
        "college",
        "schools",
        "university",
        "professional_courses",
        "distance_learning",
        "day_care",
        "coaching",
        "elearning",
        "vocational_and_trade_schools",
        "sporting_clubs",
        "dance_halls_studios_and_schools",
        "correspondence_schools",
    ],
    "healthcare": [
        "pharmacy",
        "clinic",
        "hospital",
        "lab",
        "dietician",
        "fitness",
        "health_coaching",
        "health_products",
        "drug_stores",
        "healthcare_marketplace",
        "osteopaths",
        "medical_equipment_and_supply_stores",
        "podiatrists_and_chiropodists",
        "dentists_and_orthodontists",
        "hardware_stores",
        "ophthalmologists",
        "orthopedic_goods_stores",
        "testing_laboratories",
        "doctors",
        "health_practitioners_medical_services",
    ],
    "ecommerce": [
        "ecommerce_marketplace",
        "agriculture",
        "books",
        "electronics_and_furniture",
        "coupons",
        "rental",
        "fashion_and_lifestyle",
        "gifting",
        "grocery",
        "baby_products",
        "office_supplies",
        "wholesale",
        "religious_products",
        "pet_products",
        "sports_products",
        "arts_and_collectibles",
        "sexual_wellness_products",
        "drop_shipping",
        "crypto_machinery",
        "tobacco",
        "weapons_and_ammunitions",
        "stamps_and_coins_stores",
        "office_equipment",
        "automobile_parts_and_equipements",
        "garden_supply_stores",
        "household_appliance_stores",
        "non_durable_goods",
        "pawn_shops",
        "electrical_parts_and_equipment",
        "wig_and_toupee_shops",
        "gift_novelty_and_souvenir_shops",
        "duty_free_stores",
        "office_and_commercial_furniture",
        "dry_goods",
        "books_and_publications",
        "camera_and_photographic_stores",
        "record_shops",
        "meat_supply_stores",
        "leather_goods_and_luggage",
        "snowmobile_dealers",
        "men_and_boys_clothing_stores",
        "paint_supply_stores",
        "automotive_parts",
        "jewellery_and_watch_stores",
        "auto_store_home_supply_stores",
        "tent_stores",
        "shoe_stores_retail",
        "petroleum_and_petroleum_products",
        "department_stores",
        "automotive_tire_stores",
        "sport_apparel_stores",
        "variety_stores",
        "chemicals_and_allied_products",
        "commercial_equipments",
        "fireplace_parts_and_accessories",
        "family_clothing_stores",
        "fabric_and_sewing_stores",
        "home_supply_warehouse",
        "art_supply_stores",
        "camper_recreational_and_utility_trailer_dealers",
        "clocks_and_silverware_stores",
        "discount_stores",
        "school_supplies_and_stationery",
        "second_hand_stores",
        "watch_and_jewellery_repair_stores",
        "liquor_stores",
        "boat_dealers",
        "opticians_optical_goods_and_eyeglasse_stores",
        "wholesale_footwear_stores",
        "cosmetic_stores",
        "home_furnishing_stores",
        "antique_stores",
        "plumbing_and_heating_equipment",
        "telecommunication_equipment_stores",
        "women_clothing",
        "florists",
        "computer_software_stores",
        "building_matrial_stores",
        "candy_nut_confectionery_shops",
        "glass_and_wallpaper_stores",
        "commercial_photography_and_graphic_design_services",
        "video_game_supply_stores",
        "fuel_dealers",
        "drapery_and_window_coverings_stores",
        "hearing_aids_stores",
        "automotive_paint_shops",
        "durable_goods_stores",
        "uniforms_and_commercial_clothing_stores",
        "fur_shops",
        "industrial_supplies",
        "bicycle_stores",
        "second_hand_stores",
        "motorcycle_shops_and_dealers",
        "children_and_infants_wear_stores",
        "women_accessory_stores",
        "construction_materials",
        "books_periodicals_and_newspaper",
        "floor_covering_stores",
        "crystal_and_glassware_stores",
        "accessory_and_apparel_stores",
        "hardware_equipment_and_supply_stores",
        "computers_peripheral_equipment_software",
        "automobile_and_truck_dealers",
        "aircraft_and_farm_equipment_dealers",
        "antique_shops_sales_and_repairs",
        "hearing_aids_stores",
        "music_stores",
        "furniture_and_home_furnishing_store",
    ],
    "services": [
        "repair_and_cleaning",
        "interior_design_and_architect",
        "movers_and_packers",
        "legal",
        "event_planning",
        "service_centre",
        "consulting",
        "ad_and_marketing",
        "services_classifieds",
        "multi_level_marketing",
        "construction_services",
        "architectural_services",
        "car_washes",
        "motor_home_rentals",
        "stenographic_and_secretarial_support_services",
        "chiropractors",
        "automotive_service_shops",
        "shoe_repair_shops",
        "telecommunication_service",
        "fines",
        "security_agencies",
        "tailors",
        "type_setting_and_engraving_services",
        "small_appliance_repair_shops",
        "photography_labs",
        "dry_cleaners",
        "massage_parlors",
        "electronic_repair_shops",
        "cleaning_and_sanitation_services",
        "nursing_care_facilities",
        "direct_marketing",
        "lottery",
        "veterinary_services",
        "affliated_auto_rental",
        "alimony_and_child_support",
        "airport_flying_fields",
        "golf_courses",
        "tire_retreading_and_repair_shops",
        "television_cable_services",
        "recreational_and_sporting_camps",
        "barber_and_beauty_shops",
        "agricultural_cooperatives",
        "carpentry_contractors",
        "wrecking_and_salvaging_services",
        "automobile_towing_services",
        "video_tape_rental_stores",
        "miscellaneous_repair_shops",
        "motor_homes_and_parts",
        "horse_or_dog_racing",
        "laundry_services",
        "electrical_contractors",
        "debt_marriage_personal_counseling_service",
        "air_conditioning_and_refrigeration_repair_shops",
        "credit_reporting_agencies",
        "heating_and_plumbing_contractors",
        "carpet_and_upholstery_cleaning_services",
        "swimming_pools",
        "roofing_and_metal_work_contractors",
        "internet_service_providers",
        "recreational_camps",
        "masonry_contractors",
        "exterminating_and_disinfecting_services",
        "ambulance_services",
        "funeral_services_and_crematories",
        "metal_service_centres",
        "copying_and_blueprinting_services",
        "fuel_dispensers",
        "welding_repair",
        "mobile_home_dealers",
        "concrete_work_contractors",
        "boat_rentals",
        "personal_shoppers_and_shopping_clubs",
        "door_to_door_sales",
        "travel_related_direct_marketing",
        "lottery_and_betting",
        "bands_orchestras_and_miscellaneous_entertainers",
        "furniture_repair_and_refinishing",
        "contractors",
        "direct_marketing_and_subscription_merchants",
        "typewriter_stores_sales_service_and_rentals",
        "recreation_services",
        "direct_marketing_insurance_services",
        "business_services",
        "inbound_telemarketing_merchants",
        "public_warehousing",
        "outbound_telemarketing_merchants",
        "clothing_rental_stores",
        "transportation_services",
        "electric_razor_stores",
        "service_stations",
        "photographic_studio",
        "professional_services",
    ],
    "housing": ["developer", "facility_management", "rwa", "coworking", "realestate_classifieds", "space_rental"],
    "not_for_profit": ["charity", "educational", "religious", "personal"],
    "social": [
        "matchmaking",
        "social_network",
        "messaging",
        "professional_network",
        "neighbourhood_network",
        "political_organizations",
        "automobile_associations_and_clubs",
        "country_and_athletic_clubs",
        "associations_and_membership",
    ],
    "media_and_entertainment": [
        "video_on_demand",
        "music_streaming",
        "multiplex",
        "content_and_publishing",
        "ticketing",
        "news",
        "video_game_arcades",
        "video_tape_production_and_distribution",
        "bowling_alleys",
        "billiard_and_pool_establishments",
        "amusement_parks_and_circuses",
        "ticket_agencies",
    ],
    "gaming": ["game_developer", "esports", "online_casino", "fantasy_sports", "gaming_marketplace"],
    "it_and_software": [
        "saas",
        "paas",
        "iaas",
        "consulting_and_outsourcing",
        "web_development",
        "technical_support",
        "data_processing",
    ],
    "food": [
        "online_food_ordering",
        "restaurant",
        "food_court",
        "catering",
        "alcohol",
        "restaurant_search_and_booking",
        "dairy_products",
        "bakeries",
    ],
    "utilities": [
        "electricity",
        "gas",
        "telecom",
        "water",
        "cable",
        "broadband",
        "dth",
        "internet_provider",
        "bill_and_recharge_aggregators",
    ],
    "government": ["central", "state", "intra_government_purchases", "goverment_postal_services"],
    "logistics": ["freight", "courier", "warehousing", "distribution", "end_to_end_logistics", "courier_services"],
    "tours_and_travel": [
        "aviation",
        "accommodation",
        "ota",
        "travel_agency",
        "tourist_attractions_and_exhibits",
        "timeshares",
        "aquariums_dolphinariums_and_seaquariums",
    ],
    "transport": [
        "cab_hailing",
        "bus",
        "train_and_metro",
        "automobile_rentals",
        "cruise_lines",
        "parking_lots_and_garages",
        "transportation",
        "bridge_and_road_tolls",
        "freight_transport",
        "truck_and_utility_trailer_rentals",
    ],
    "others": [],  # No sub-categories specified
}


class BusinessCategoryResponse(BaseModel):
    categories: List[str]
    sub_categories: Dict[str, List[str]]
