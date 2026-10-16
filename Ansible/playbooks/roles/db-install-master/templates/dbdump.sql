--
-- PostgreSQL database dump
--

-- Dumped from database version 17.2
-- Dumped by pg_dump version 17.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: bot; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.bot (
    id integer NOT NULL,
    name character varying(16) NOT NULL,
    description text,
    runsetting_id integer,
    user_id integer,
    indicatorchain_id integer
);


ALTER TABLE public.bot OWNER TO twats;

--
-- Name: bot_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.bot_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.bot_id_seq OWNER TO twats;

--
-- Name: bot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.bot_id_seq OWNED BY public.bot.id;


--
-- Name: candle; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.candle (
    id integer NOT NULL,
    "timestamp" timestamp with time zone NOT NULL,
    open real DEFAULT '0'::real NOT NULL,
    low real DEFAULT '0'::real NOT NULL,
    high real DEFAULT '0'::real NOT NULL,
    close real DEFAULT '0'::real NOT NULL,
    volume real DEFAULT '0'::real NOT NULL,
    type integer NOT NULL,
    market_id integer,
    period_id integer
);


ALTER TABLE public.candle OWNER TO twats;

--
-- Name: candle_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.candle_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.candle_id_seq OWNER TO twats;

--
-- Name: candle_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.candle_id_seq OWNED BY public.candle.id;


--
-- Name: config; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.config (
    id integer NOT NULL,
    name character varying NOT NULL,
    description character varying NOT NULL,
    value character varying NOT NULL
);


ALTER TABLE public.config OWNER TO twats;

--
-- Name: config_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.config_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.config_id_seq OWNER TO twats;

--
-- Name: config_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.config_id_seq OWNED BY public.config.id;


--
-- Name: exchange; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.exchange (
    id integer NOT NULL,
    name character varying(16) DEFAULT ''::character varying NOT NULL,
    namelib character varying(16),
    testsupport boolean DEFAULT false NOT NULL,
    helpertype character varying(24) DEFAULT 'SourceCcxtHelper'::character varying NOT NULL,
    markettype character varying(16) DEFAULT 'spot'::character varying NOT NULL,
    maxleverage integer DEFAULT 1 NOT NULL,
    active boolean DEFAULT false NOT NULL,
    real_trading boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    publicauth boolean DEFAULT false NOT NULL,
    has_order_expire boolean DEFAULT false NOT NULL,
    time_open timestamp with time zone,
    time_close timestamp with time zone,
    we_closed boolean DEFAULT false NOT NULL,
    time_open_we timestamp with time zone,
    time_close_we timestamp with time zone
);


ALTER TABLE public.exchange OWNER TO twats;

--
-- Name: exchange_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.exchange_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.exchange_id_seq OWNER TO twats;

--
-- Name: exchange_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.exchange_id_seq OWNED BY public.exchange.id;


--
-- Name: exchange_periods_period; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.exchange_periods_period (
    "exchangeId" integer NOT NULL,
    "periodId" integer NOT NULL
);


ALTER TABLE public.exchange_periods_period OWNER TO twats;

--
-- Name: indicatorchain; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.indicatorchain (
    id integer NOT NULL,
    name character varying(64) NOT NULL,
    indicators_json character varying NOT NULL,
    indicatorss_json character varying,
    user_id integer
);


ALTER TABLE public.indicatorchain OWNER TO twats;

--
-- Name: indicatorchain_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.indicatorchain_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.indicatorchain_id_seq OWNER TO twats;

--
-- Name: indicatorchain_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.indicatorchain_id_seq OWNED BY public.indicatorchain.id;


--
-- Name: market; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.market (
    id integer NOT NULL,
    symbol character varying(32) NOT NULL,
    fees_maker real DEFAULT '0.001'::real NOT NULL,
    fees_taker real DEFAULT '0.005'::real NOT NULL,
    tier_based boolean DEFAULT false NOT NULL,
    active boolean DEFAULT false NOT NULL,
    type character varying DEFAULT 'spot'::character varying NOT NULL,
    leverage real DEFAULT '1'::real NOT NULL,
    exchange_id integer
);


ALTER TABLE public.market OWNER TO twats;

--
-- Name: market_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.market_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.market_id_seq OWNER TO twats;

--
-- Name: market_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.market_id_seq OWNED BY public.market.id;


--
-- Name: marketloading; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.marketloading (
    id integer NOT NULL,
    loading boolean NOT NULL,
    state character varying(16) NOT NULL,
    statecomment character varying(512),
    percent real DEFAULT '0'::real NOT NULL,
    date_started timestamp with time zone NOT NULL,
    date_finished timestamp with time zone NOT NULL,
    lastcandle timestamp with time zone,
    market_id integer,
    period_id integer
);


ALTER TABLE public.marketloading OWNER TO twats;

--
-- Name: marketloading_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.marketloading_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.marketloading_id_seq OWNER TO twats;

--
-- Name: marketloading_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.marketloading_id_seq OWNED BY public.marketloading.id;


--
-- Name: news; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.news (
    id integer NOT NULL,
    title character varying(64) NOT NULL,
    description text,
    language character varying(8) DEFAULT 'en'::character varying NOT NULL,
    sticky boolean DEFAULT false NOT NULL,
    private boolean DEFAULT false NOT NULL,
    carousel boolean DEFAULT false NOT NULL,
    date_created timestamp without time zone,
    date_updated timestamp without time zone,
    date_deleted timestamp without time zone,
    owner_id integer
);


ALTER TABLE public.news OWNER TO twats;

--
-- Name: news_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.news_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.news_id_seq OWNER TO twats;

--
-- Name: news_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.news_id_seq OWNED BY public.news.id;


--
-- Name: period; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.period (
    id integer NOT NULL,
    name character varying(8) NOT NULL,
    seconds integer NOT NULL,
    active boolean DEFAULT true NOT NULL
);


ALTER TABLE public.period OWNER TO twats;

--
-- Name: period_exchanges_exchange; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.period_exchanges_exchange (
    "periodId" integer NOT NULL,
    "exchangeId" integer NOT NULL
);


ALTER TABLE public.period_exchanges_exchange OWNER TO twats;

--
-- Name: period_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.period_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.period_id_seq OWNER TO twats;

--
-- Name: period_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.period_id_seq OWNED BY public.period.id;


--
-- Name: referral; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.referral (
    id integer NOT NULL,
    date timestamp without time zone NOT NULL,
    active boolean NOT NULL,
    referrer integer,
    referred integer
);


ALTER TABLE public.referral OWNER TO twats;

--
-- Name: referral_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.referral_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.referral_id_seq OWNER TO twats;

--
-- Name: referral_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.referral_id_seq OWNED BY public.referral.id;


--
-- Name: run; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.run (
    id integer NOT NULL,
    name character varying(128) DEFAULT 'NONAME'::character varying NOT NULL,
    testmode integer DEFAULT 2 NOT NULL,
    testbegin timestamp with time zone,
    testend timestamp with time zone,
    testcurrent timestamp with time zone,
    date_begin timestamp with time zone,
    date_end timestamp with time zone,
    winrate real,
    riskreward real,
    state character varying(16) NOT NULL,
    state_old character varying(16),
    state_percent real DEFAULT '0'::real NOT NULL,
    state_comment text,
    duration real DEFAULT '0'::real NOT NULL,
    test_balancebegin real DEFAULT '1000'::real NOT NULL,
    test_balanceend real DEFAULT '0'::real NOT NULL,
    test_balancemin real DEFAULT '0'::real NOT NULL,
    log text,
    errlog text,
    nbwin integer DEFAULT 0 NOT NULL,
    nbloss integer DEFAULT 0 NOT NULL,
    nbcancel integer DEFAULT 0 NOT NULL,
    nbweakmarge integer DEFAULT 0 NOT NULL,
    nbtrades integer DEFAULT 0 NOT NULL,
    nbopportunities integer DEFAULT 0 NOT NULL,
    retcode integer,
    pid integer,
    sumgains real DEFAULT '0'::real NOT NULL,
    sumlosses real DEFAULT '0'::real NOT NULL,
    sumgainsnet real DEFAULT '0'::real NOT NULL,
    sumlossesnet real DEFAULT '0'::real NOT NULL,
    sumbought real DEFAULT '0'::real NOT NULL,
    sumboughtnet real DEFAULT '0'::real NOT NULL,
    date_create timestamp with time zone DEFAULT now() NOT NULL,
    date_update timestamp with time zone,
    server boolean DEFAULT false NOT NULL,
    resume boolean DEFAULT false NOT NULL,
    user_id integer,
    market_id integer,
    period_id integer,
    bot_id integer
);


ALTER TABLE public.run OWNER TO twats;

--
-- Name: run_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.run_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.run_id_seq OWNER TO twats;

--
-- Name: run_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.run_id_seq OWNED BY public.run.id;


--
-- Name: runorder; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.runorder (
    id integer NOT NULL,
    tradetype character varying(8) NOT NULL,
    date_create timestamp with time zone NOT NULL,
    dateexec_buy timestamp with time zone,
    dateexec_tp timestamp with time zone,
    dateexec_sl timestamp with time zone,
    amount real NOT NULL,
    pricebuy real NOT NULL,
    pricetp real NOT NULL,
    pricesl real NOT NULL,
    pricesl_final real NOT NULL,
    pricebase real NOT NULL,
    orderid_buy character varying,
    orderid_tp character varying,
    orderid_sl character varying,
    status character varying(8) DEFAULT 'open'::character varying NOT NULL,
    status_buy character varying(8) DEFAULT 'open'::character varying NOT NULL,
    status_tp character varying(8),
    status_sl character varying(8),
    typebuy character varying(8) DEFAULT 'maker'::character varying NOT NULL,
    typetp character varying(8) DEFAULT 'maker'::character varying NOT NULL,
    typesl character varying(8) DEFAULT 'maker'::character varying NOT NULL,
    realrr real DEFAULT '0'::real NOT NULL,
    runorder_id integer DEFAULT 0 NOT NULL,
    typeorderbuy character varying(8) DEFAULT 'limit'::character varying NOT NULL,
    typeordertp character varying(8) DEFAULT 'limit'::character varying NOT NULL,
    typeordersl character varying(8) DEFAULT 'limit'::character varying NOT NULL,
    leverage real DEFAULT '1'::real NOT NULL,
    marge real DEFAULT '0'::real NOT NULL,
    won boolean DEFAULT false NOT NULL,
    weakmarge boolean DEFAULT false NOT NULL,
    run_id integer
);


ALTER TABLE public.runorder OWNER TO twats;

--
-- Name: runorder_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.runorder_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.runorder_id_seq OWNER TO twats;

--
-- Name: runorder_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.runorder_id_seq OWNED BY public.runorder.id;


--
-- Name: runsetting; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.runsetting (
    id integer NOT NULL,
    name character varying(64),
    leverage integer NOT NULL,
    minmarge real DEFAULT '0.1'::real NOT NULL,
    riskreward real DEFAULT '2'::real NOT NULL,
    stoplossmarge real DEFAULT '0'::real NOT NULL,
    trailingstopat real DEFAULT '100'::real NOT NULL,
    requireminmarge boolean DEFAULT false NOT NULL,
    riskpertrade character varying(8) NOT NULL,
    fees_taker real DEFAULT '0'::real NOT NULL,
    fees_maker real DEFAULT '0'::real NOT NULL,
    nb_period_expiration integer DEFAULT 3 NOT NULL,
    recursive boolean DEFAULT false NOT NULL,
    user_id integer
);


ALTER TABLE public.runsetting OWNER TO twats;

--
-- Name: runsetting_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.runsetting_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.runsetting_id_seq OWNER TO twats;

--
-- Name: runsetting_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.runsetting_id_seq OWNED BY public.runsetting.id;


--
-- Name: sublevel; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.sublevel (
    id integer NOT NULL,
    name character varying(32) NOT NULL,
    amount real NOT NULL,
    tax real DEFAULT '10'::real NOT NULL,
    testrate real DEFAULT '0.5'::real NOT NULL,
    maxbottest integer NOT NULL,
    maxbotprod integer NOT NULL,
    maxsimultrades integer DEFAULT 1 NOT NULL,
    maxindicators integer DEFAULT 2 NOT NULL,
    serverbots integer DEFAULT 0 NOT NULL,
    maxindicatorchains integer DEFAULT 1 NOT NULL,
    maxbotmarkets integer DEFAULT 1 NOT NULL,
    indicatorlevel integer DEFAULT 1 NOT NULL
);


ALTER TABLE public.sublevel OWNER TO twats;

--
-- Name: sublevel_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.sublevel_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.sublevel_id_seq OWNER TO twats;

--
-- Name: sublevel_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.sublevel_id_seq OWNED BY public.sublevel.id;


--
-- Name: sublevellog; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.sublevellog (
    id integer NOT NULL,
    date_begin timestamp with time zone,
    date_end timestamp with time zone,
    reason_end character varying(64),
    user_id integer,
    sublevel_id integer
);


ALTER TABLE public.sublevellog OWNER TO twats;

--
-- Name: sublevellog_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.sublevellog_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.sublevellog_id_seq OWNER TO twats;

--
-- Name: sublevellog_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.sublevellog_id_seq OWNED BY public.sublevellog.id;


--
-- Name: user; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public."user" (
    id integer NOT NULL,
    address character varying(320) NOT NULL,
    nonce character varying(320),
    signature character varying(320),
    date_lastconnect timestamp with time zone,
    date_lastsignin timestamp with time zone,
    last_wallet character varying(320),
    chain_id character varying(320),
    nickname character varying(32),
    firstname character varying(32),
    lastname character varying(32),
    utcoffset integer DEFAULT 0 NOT NULL,
    email character varying(256),
    prowlapikey character varying(256),
    date_create timestamp with time zone NOT NULL,
    date_update timestamp with time zone,
    date_delete timestamp with time zone,
    locale character varying(8) DEFAULT 'en'::character varying NOT NULL,
    referral_code character varying(32) NOT NULL,
    subchain character varying(64),
    admin boolean NOT NULL,
    active boolean DEFAULT true NOT NULL,
    sublevel_id integer
);


ALTER TABLE public."user" OWNER TO twats;

--
-- Name: user_apikey; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.user_apikey (
    id integer NOT NULL,
    lkey character varying(128) NOT NULL,
    psecret character varying(128) NOT NULL,
    pphrase character varying(512),
    lkey_test character varying(128),
    psecret_test character varying(128),
    idlive character varying(32),
    idtest character varying(32),
    username character varying(128),
    password character varying(128),
    address character varying(320),
    user_id integer,
    exchange_id integer
);


ALTER TABLE public.user_apikey OWNER TO twats;

--
-- Name: user_apikey_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.user_apikey_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_apikey_id_seq OWNER TO twats;

--
-- Name: user_apikey_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.user_apikey_id_seq OWNED BY public.user_apikey.id;


--
-- Name: user_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_id_seq OWNER TO twats;

--
-- Name: user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.user_id_seq OWNED BY public."user".id;


--
-- Name: userbalance; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.userbalance (
    id integer NOT NULL,
    amount real NOT NULL,
    currency_id integer NOT NULL,
    user_id integer,
    exchange_id integer
);


ALTER TABLE public.userbalance OWNER TO twats;

--
-- Name: userbalance_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.userbalance_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.userbalance_id_seq OWNER TO twats;

--
-- Name: userbalance_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.userbalance_id_seq OWNED BY public.userbalance.id;


--
-- Name: userconnection; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.userconnection (
    id integer NOT NULL,
    date timestamp with time zone NOT NULL,
    ip character varying(128) NOT NULL,
    ip2 character varying(128),
    domain character varying(256),
    "full" boolean DEFAULT false NOT NULL,
    user_agent character varying(256),
    referer character varying(256),
    platform character varying(128),
    browser character varying(128),
    user_id integer
);


ALTER TABLE public.userconnection OWNER TO twats;

--
-- Name: userconnection_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.userconnection_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.userconnection_id_seq OWNER TO twats;

--
-- Name: userconnection_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.userconnection_id_seq OWNED BY public.userconnection.id;


--
-- Name: userfees; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.userfees (
    id integer NOT NULL,
    fees_maker real NOT NULL,
    fees_taker real NOT NULL,
    user_id integer,
    market_id integer
);


ALTER TABLE public.userfees OWNER TO twats;

--
-- Name: userfees_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.userfees_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.userfees_id_seq OWNER TO twats;

--
-- Name: userfees_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.userfees_id_seq OWNED BY public.userfees.id;


--
-- Name: usernonce; Type: TABLE; Schema: public; Owner: twats
--

CREATE TABLE public.usernonce (
    id integer NOT NULL,
    nonce character varying NOT NULL,
    date_created timestamp without time zone NOT NULL,
    date_ended timestamp without time zone,
    user_id integer
);


ALTER TABLE public.usernonce OWNER TO twats;

--
-- Name: usernonce_id_seq; Type: SEQUENCE; Schema: public; Owner: twats
--

CREATE SEQUENCE public.usernonce_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.usernonce_id_seq OWNER TO twats;

--
-- Name: usernonce_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: twats
--

ALTER SEQUENCE public.usernonce_id_seq OWNED BY public.usernonce.id;


--
-- Name: bot id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.bot ALTER COLUMN id SET DEFAULT nextval('public.bot_id_seq'::regclass);


--
-- Name: candle id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.candle ALTER COLUMN id SET DEFAULT nextval('public.candle_id_seq'::regclass);


--
-- Name: config id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.config ALTER COLUMN id SET DEFAULT nextval('public.config_id_seq'::regclass);


--
-- Name: exchange id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.exchange ALTER COLUMN id SET DEFAULT nextval('public.exchange_id_seq'::regclass);


--
-- Name: indicatorchain id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.indicatorchain ALTER COLUMN id SET DEFAULT nextval('public.indicatorchain_id_seq'::regclass);


--
-- Name: market id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.market ALTER COLUMN id SET DEFAULT nextval('public.market_id_seq'::regclass);


--
-- Name: marketloading id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.marketloading ALTER COLUMN id SET DEFAULT nextval('public.marketloading_id_seq'::regclass);


--
-- Name: news id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.news ALTER COLUMN id SET DEFAULT nextval('public.news_id_seq'::regclass);


--
-- Name: period id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.period ALTER COLUMN id SET DEFAULT nextval('public.period_id_seq'::regclass);


--
-- Name: referral id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.referral ALTER COLUMN id SET DEFAULT nextval('public.referral_id_seq'::regclass);


--
-- Name: run id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.run ALTER COLUMN id SET DEFAULT nextval('public.run_id_seq'::regclass);


--
-- Name: runorder id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.runorder ALTER COLUMN id SET DEFAULT nextval('public.runorder_id_seq'::regclass);


--
-- Name: runsetting id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.runsetting ALTER COLUMN id SET DEFAULT nextval('public.runsetting_id_seq'::regclass);


--
-- Name: sublevel id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.sublevel ALTER COLUMN id SET DEFAULT nextval('public.sublevel_id_seq'::regclass);


--
-- Name: sublevellog id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.sublevellog ALTER COLUMN id SET DEFAULT nextval('public.sublevellog_id_seq'::regclass);


--
-- Name: user id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public."user" ALTER COLUMN id SET DEFAULT nextval('public.user_id_seq'::regclass);


--
-- Name: user_apikey id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.user_apikey ALTER COLUMN id SET DEFAULT nextval('public.user_apikey_id_seq'::regclass);


--
-- Name: userbalance id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userbalance ALTER COLUMN id SET DEFAULT nextval('public.userbalance_id_seq'::regclass);


--
-- Name: userconnection id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userconnection ALTER COLUMN id SET DEFAULT nextval('public.userconnection_id_seq'::regclass);


--
-- Name: userfees id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userfees ALTER COLUMN id SET DEFAULT nextval('public.userfees_id_seq'::regclass);


--
-- Name: usernonce id; Type: DEFAULT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.usernonce ALTER COLUMN id SET DEFAULT nextval('public.usernonce_id_seq'::regclass);


--
-- Data for Name: bot; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.bot (id, name, description, runsetting_id, user_id, indicatorchain_id) FROM stdin;
\.


--
-- Data for Name: candle; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.candle (id, "timestamp", open, low, high, close, volume, type, market_id, period_id) FROM stdin;
\.


--
-- Data for Name: config; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.config (id, name, description, value) FROM stdin;
\.


--
-- Data for Name: exchange; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.exchange (id, name, namelib, testsupport, helpertype, markettype, maxleverage, active, real_trading, enabled, publicauth, has_order_expire, time_open, time_close, we_closed, time_open_we, time_close_we) FROM stdin;
1	Binance	binance	t	SourceCcxtHelper		0	f	f	f	f	f	\N	\N	f	\N	\N
2	Bitget	bitget	t	SourceCcxtHelper		0	f	f	f	f	f	\N	\N	f	\N	\N
\.


--
-- Data for Name: exchange_periods_period; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.exchange_periods_period ("exchangeId", "periodId") FROM stdin;
1	1
1	2
1	3
1	4
1	5
1	6
1	7
1	8
1	9
1	10
1	11
1	12
1	13
\.


--
-- Data for Name: indicatorchain; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.indicatorchain (id, name, indicators_json, indicatorss_json, user_id) FROM stdin;
\.


--
-- Data for Name: market; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.market (id, symbol, fees_maker, fees_taker, tier_based, active, type, leverage, exchange_id) FROM stdin;
1	BTC/USDC	0.001	0.001	f	f	spot	1	1
\.


--
-- Data for Name: marketloading; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.marketloading (id, loading, state, statecomment, percent, date_started, date_finished, lastcandle, market_id, period_id) FROM stdin;
1	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	1
2	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	11
3	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	7
4	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	6
6	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	2
5	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	3
7	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	10
9	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	4
11	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	9
8	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	5
12	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	12
10	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	8
13	f	Empty	\N	0	2025-04-12 17:36:57.641+00	2025-04-12 17:36:57.641+00	\N	1	13
\.


--
-- Data for Name: news; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.news (id, title, description, language, sticky, private, carousel, date_created, date_updated, date_deleted, owner_id) FROM stdin;
\.


--
-- Data for Name: period; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.period (id, name, seconds, active) FROM stdin;
1	1m	60	t
2	3m	180	t
3	5m	300	t
4	15m	900	t
5	30m	1800	t
6	1h	3600	t
7	2h	7200	t
8	4h	14400	t
9	6h	21600	t
10	8h	28800	t
11	12h	43200	t
12	1d	86400	t
13	3d	259200	t
14	1w	604800	t
\.


--
-- Data for Name: period_exchanges_exchange; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.period_exchanges_exchange ("periodId", "exchangeId") FROM stdin;
\.


--
-- Data for Name: referral; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.referral (id, date, active, referrer, referred) FROM stdin;
\.


--
-- Data for Name: run; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.run (id, name, testmode, testbegin, testend, testcurrent, date_begin, date_end, winrate, riskreward, state, state_old, state_percent, state_comment, duration, test_balancebegin, test_balanceend, test_balancemin, log, errlog, nbwin, nbloss, nbcancel, nbweakmarge, nbtrades, nbopportunities, retcode, pid, sumgains, sumlosses, sumgainsnet, sumlossesnet, sumbought, sumboughtnet, date_create, date_update, server, resume, user_id, market_id, period_id, bot_id) FROM stdin;
\.


--
-- Data for Name: runorder; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.runorder (id, tradetype, date_create, dateexec_buy, dateexec_tp, dateexec_sl, amount, pricebuy, pricetp, pricesl, pricesl_final, pricebase, orderid_buy, orderid_tp, orderid_sl, status, status_buy, status_tp, status_sl, typebuy, typetp, typesl, realrr, runorder_id, typeorderbuy, typeordertp, typeordersl, leverage, marge, won, weakmarge, run_id) FROM stdin;
\.


--
-- Data for Name: runsetting; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.runsetting (id, name, leverage, minmarge, riskreward, stoplossmarge, trailingstopat, requireminmarge, riskpertrade, fees_taker, fees_maker, nb_period_expiration, recursive, user_id) FROM stdin;
\.


--
-- Data for Name: sublevel; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.sublevel (id, name, amount, tax, testrate, maxbottest, maxbotprod, maxsimultrades, maxindicators, serverbots, maxindicatorchains, maxbotmarkets, indicatorlevel) FROM stdin;
\.


--
-- Data for Name: sublevellog; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.sublevellog (id, date_begin, date_end, reason_end, user_id, sublevel_id) FROM stdin;
\.


--
-- Data for Name: user; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public."user" (id, address, nonce, signature, date_lastconnect, date_lastsignin, last_wallet, chain_id, nickname, firstname, lastname, utcoffset, email, prowlapikey, date_create, date_update, date_delete, locale, referral_code, subchain, admin, active, sublevel_id) FROM stdin;
\.


--
-- Data for Name: user_apikey; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.user_apikey (id, lkey, psecret, pphrase, lkey_test, psecret_test, idlive, idtest, username, password, address, user_id, exchange_id) FROM stdin;
\.


--
-- Data for Name: userbalance; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.userbalance (id, amount, currency_id, user_id, exchange_id) FROM stdin;
\.


--
-- Data for Name: userconnection; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.userconnection (id, date, ip, ip2, domain, "full", user_agent, referer, platform, browser, user_id) FROM stdin;
\.


--
-- Data for Name: userfees; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.userfees (id, fees_maker, fees_taker, user_id, market_id) FROM stdin;
\.


--
-- Data for Name: usernonce; Type: TABLE DATA; Schema: public; Owner: twats
--

COPY public.usernonce (id, nonce, date_created, date_ended, user_id) FROM stdin;
\.


--
-- Name: bot_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.bot_id_seq', 1, false);


--
-- Name: candle_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.candle_id_seq', 1, false);


--
-- Name: config_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.config_id_seq', 1, false);


--
-- Name: exchange_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.exchange_id_seq', 2, true);


--
-- Name: indicatorchain_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.indicatorchain_id_seq', 1, false);


--
-- Name: market_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.market_id_seq', 1, true);


--
-- Name: marketloading_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.marketloading_id_seq', 13, true);


--
-- Name: news_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.news_id_seq', 1, false);


--
-- Name: period_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.period_id_seq', 14, true);


--
-- Name: referral_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.referral_id_seq', 1, false);


--
-- Name: run_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.run_id_seq', 1, false);


--
-- Name: runorder_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.runorder_id_seq', 1, false);


--
-- Name: runsetting_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.runsetting_id_seq', 1, false);


--
-- Name: sublevel_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.sublevel_id_seq', 1, false);


--
-- Name: sublevellog_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.sublevellog_id_seq', 1, false);


--
-- Name: user_apikey_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.user_apikey_id_seq', 1, false);


--
-- Name: user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.user_id_seq', 3, true);


--
-- Name: userbalance_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.userbalance_id_seq', 1, false);


--
-- Name: userconnection_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.userconnection_id_seq', 176, true);


--
-- Name: userfees_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.userfees_id_seq', 1, false);


--
-- Name: usernonce_id_seq; Type: SEQUENCE SET; Schema: public; Owner: twats
--

SELECT pg_catalog.setval('public.usernonce_id_seq', 153, true);


--
-- Name: runsetting PK_1b2b38a4ad3c83868cf3e4ddbd7; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.runsetting
    ADD CONSTRAINT "PK_1b2b38a4ad3c83868cf3e4ddbd7" PRIMARY KEY (id);


--
-- Name: market PK_1e9a2963edfd331d92018e3abac; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.market
    ADD CONSTRAINT "PK_1e9a2963edfd331d92018e3abac" PRIMARY KEY (id);


--
-- Name: user_apikey PK_267fcb35245e0b81150b141d8d2; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.user_apikey
    ADD CONSTRAINT "PK_267fcb35245e0b81150b141d8d2" PRIMARY KEY (id);


--
-- Name: period_exchanges_exchange PK_2bbfc2082c57b6673322d2fc706; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.period_exchanges_exchange
    ADD CONSTRAINT "PK_2bbfc2082c57b6673322d2fc706" PRIMARY KEY ("periodId", "exchangeId");


--
-- Name: marketloading PK_2c8db67c5a10a812c0c46d2dddb; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.marketloading
    ADD CONSTRAINT "PK_2c8db67c5a10a812c0c46d2dddb" PRIMARY KEY (id);


--
-- Name: news PK_39a43dfcb6007180f04aff2357e; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.news
    ADD CONSTRAINT "PK_39a43dfcb6007180f04aff2357e" PRIMARY KEY (id);


--
-- Name: usernonce PK_4281666d2a6fdcc5db302ef1295; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.usernonce
    ADD CONSTRAINT "PK_4281666d2a6fdcc5db302ef1295" PRIMARY KEY (id);


--
-- Name: runorder PK_532f0b504b5ff36513bf284a699; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.runorder
    ADD CONSTRAINT "PK_532f0b504b5ff36513bf284a699" PRIMARY KEY (id);


--
-- Name: run PK_804c38ffba92002c6d2c646dd46; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.run
    ADD CONSTRAINT "PK_804c38ffba92002c6d2c646dd46" PRIMARY KEY (id);


--
-- Name: userbalance PK_85a041ff5e17605cde455963b97; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userbalance
    ADD CONSTRAINT "PK_85a041ff5e17605cde455963b97" PRIMARY KEY (id);


--
-- Name: exchange_periods_period PK_9373d362b8c8295a4a678db8472; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.exchange_periods_period
    ADD CONSTRAINT "PK_9373d362b8c8295a4a678db8472" PRIMARY KEY ("exchangeId", "periodId");


--
-- Name: referral PK_a2d3e935a6591168066defec5ad; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.referral
    ADD CONSTRAINT "PK_a2d3e935a6591168066defec5ad" PRIMARY KEY (id);


--
-- Name: userconnection PK_a7d202ffa5cd03149856faa187a; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userconnection
    ADD CONSTRAINT "PK_a7d202ffa5cd03149856faa187a" PRIMARY KEY (id);


--
-- Name: sublevel PK_aff07a66e8c53a3beaee172c44b; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.sublevel
    ADD CONSTRAINT "PK_aff07a66e8c53a3beaee172c44b" PRIMARY KEY (id);


--
-- Name: bot PK_bc6d59d7870eb2efd5f7f61e5ca; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.bot
    ADD CONSTRAINT "PK_bc6d59d7870eb2efd5f7f61e5ca" PRIMARY KEY (id);


--
-- Name: period PK_cabecec858892ab647cd28673b8; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.period
    ADD CONSTRAINT "PK_cabecec858892ab647cd28673b8" PRIMARY KEY (id);


--
-- Name: user PK_cace4a159ff9f2512dd42373760; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT "PK_cace4a159ff9f2512dd42373760" PRIMARY KEY (id);


--
-- Name: userfees PK_cb6c3f04ee9b16f758eed8f108b; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userfees
    ADD CONSTRAINT "PK_cb6c3f04ee9b16f758eed8f108b" PRIMARY KEY (id);


--
-- Name: exchange PK_cbd4568fcb476b57cebd8239895; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.exchange
    ADD CONSTRAINT "PK_cbd4568fcb476b57cebd8239895" PRIMARY KEY (id);


--
-- Name: config PK_d0ee79a681413d50b0a4f98cf7b; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.config
    ADD CONSTRAINT "PK_d0ee79a681413d50b0a4f98cf7b" PRIMARY KEY (id);


--
-- Name: indicatorchain PK_de9ecddd72a4d350a669fc5a31b; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.indicatorchain
    ADD CONSTRAINT "PK_de9ecddd72a4d350a669fc5a31b" PRIMARY KEY (id);


--
-- Name: candle PK_e4bfba00b826f30058f10eb59d0; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.candle
    ADD CONSTRAINT "PK_e4bfba00b826f30058f10eb59d0" PRIMARY KEY (id);


--
-- Name: sublevellog PK_f452b19854ba69ffc0c13a705af; Type: CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.sublevellog
    ADD CONSTRAINT "PK_f452b19854ba69ffc0c13a705af" PRIMARY KEY (id);


--
-- Name: IDX_450efe7ec25168dab77b6adc1d; Type: INDEX; Schema: public; Owner: twats
--

CREATE INDEX "IDX_450efe7ec25168dab77b6adc1d" ON public.exchange_periods_period USING btree ("exchangeId");


--
-- Name: IDX_9d602929aa8b31e01c1090c7ca; Type: INDEX; Schema: public; Owner: twats
--

CREATE INDEX "IDX_9d602929aa8b31e01c1090c7ca" ON public.period_exchanges_exchange USING btree ("exchangeId");


--
-- Name: IDX_d85d0dad66f034e63ee1ecbfa9; Type: INDEX; Schema: public; Owner: twats
--

CREATE INDEX "IDX_d85d0dad66f034e63ee1ecbfa9" ON public.exchange_periods_period USING btree ("periodId");


--
-- Name: IDX_f6472a151197e6bb0ca51ee644; Type: INDEX; Schema: public; Owner: twats
--

CREATE INDEX "IDX_f6472a151197e6bb0ca51ee644" ON public.period_exchanges_exchange USING btree ("periodId");


--
-- Name: candle_id_UNIQUE; Type: INDEX; Schema: public; Owner: twats
--

CREATE UNIQUE INDEX "candle_id_UNIQUE" ON public.candle USING btree ("timestamp", market_id, period_id);


--
-- Name: marketloading_id_UNIQUE; Type: INDEX; Schema: public; Owner: twats
--

CREATE UNIQUE INDEX "marketloading_id_UNIQUE" ON public.marketloading USING btree (market_id, period_id);


--
-- Name: sublevellog FK_01268d16498958ff90f9d25b247; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.sublevellog
    ADD CONSTRAINT "FK_01268d16498958ff90f9d25b247" FOREIGN KEY (sublevel_id) REFERENCES public.sublevel(id);


--
-- Name: referral FK_03f09bcde38092a416360cecd68; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.referral
    ADD CONSTRAINT "FK_03f09bcde38092a416360cecd68" FOREIGN KEY (referred) REFERENCES public."user"(id);


--
-- Name: indicatorchain FK_0cab2d9123e7ad0e2d8d3d14376; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.indicatorchain
    ADD CONSTRAINT "FK_0cab2d9123e7ad0e2d8d3d14376" FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: marketloading FK_0dd5c34fcb33d9092e5e5998a7c; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.marketloading
    ADD CONSTRAINT "FK_0dd5c34fcb33d9092e5e5998a7c" FOREIGN KEY (period_id) REFERENCES public.period(id);


--
-- Name: user FK_13ce9045fbf9a5952009539f148; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT "FK_13ce9045fbf9a5952009539f148" FOREIGN KEY (sublevel_id) REFERENCES public.sublevel(id);


--
-- Name: marketloading FK_1beedbf9adaf23f1fa3e6c7bed9; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.marketloading
    ADD CONSTRAINT "FK_1beedbf9adaf23f1fa3e6c7bed9" FOREIGN KEY (market_id) REFERENCES public.market(id);


--
-- Name: user_apikey FK_1c7f519330e6d333a5c1b6fc8ae; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.user_apikey
    ADD CONSTRAINT "FK_1c7f519330e6d333a5c1b6fc8ae" FOREIGN KEY (exchange_id) REFERENCES public.exchange(id);


--
-- Name: user_apikey FK_2204fa1f7ef860d425b49c2d9d6; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.user_apikey
    ADD CONSTRAINT "FK_2204fa1f7ef860d425b49c2d9d6" FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: bot FK_2f8bfddf2a5790822047ac85876; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.bot
    ADD CONSTRAINT "FK_2f8bfddf2a5790822047ac85876" FOREIGN KEY (indicatorchain_id) REFERENCES public.indicatorchain(id);


--
-- Name: userconnection FK_2fd0b0f9bd8b0358f604f96d9ef; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userconnection
    ADD CONSTRAINT "FK_2fd0b0f9bd8b0358f604f96d9ef" FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: userfees FK_3324943237da63ebd44fb86b318; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userfees
    ADD CONSTRAINT "FK_3324943237da63ebd44fb86b318" FOREIGN KEY (market_id) REFERENCES public.market(id);


--
-- Name: bot FK_3dc8c0cfcb9eb7860c9179d1591; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.bot
    ADD CONSTRAINT "FK_3dc8c0cfcb9eb7860c9179d1591" FOREIGN KEY (runsetting_id) REFERENCES public.runsetting(id);


--
-- Name: exchange_periods_period FK_450efe7ec25168dab77b6adc1dc; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.exchange_periods_period
    ADD CONSTRAINT "FK_450efe7ec25168dab77b6adc1dc" FOREIGN KEY ("exchangeId") REFERENCES public.exchange(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: run FK_5f8a163e576ca7272e869ac9713; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.run
    ADD CONSTRAINT "FK_5f8a163e576ca7272e869ac9713" FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: runorder FK_67de897ad4adf0cf8882dda4a7c; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.runorder
    ADD CONSTRAINT "FK_67de897ad4adf0cf8882dda4a7c" FOREIGN KEY (run_id) REFERENCES public.run(id);


--
-- Name: run FK_6f7852dc74d5d831f865090e2d5; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.run
    ADD CONSTRAINT "FK_6f7852dc74d5d831f865090e2d5" FOREIGN KEY (bot_id) REFERENCES public.bot(id);


--
-- Name: candle FK_8958d614fad57b28aebf28604a5; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.candle
    ADD CONSTRAINT "FK_8958d614fad57b28aebf28604a5" FOREIGN KEY (period_id) REFERENCES public.period(id);


--
-- Name: candle FK_8e33c6b56d38a06d01e3df8962e; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.candle
    ADD CONSTRAINT "FK_8e33c6b56d38a06d01e3df8962e" FOREIGN KEY (market_id) REFERENCES public.market(id);


--
-- Name: period_exchanges_exchange FK_9d602929aa8b31e01c1090c7cad; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.period_exchanges_exchange
    ADD CONSTRAINT "FK_9d602929aa8b31e01c1090c7cad" FOREIGN KEY ("exchangeId") REFERENCES public.exchange(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: bot FK_a3190460df612af6ab214b44a92; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.bot
    ADD CONSTRAINT "FK_a3190460df612af6ab214b44a92" FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: sublevellog FK_a8daa85a727fbfd8e5fd5ab3fcb; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.sublevellog
    ADD CONSTRAINT "FK_a8daa85a727fbfd8e5fd5ab3fcb" FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: run FK_c0e8aa62541a592554607dea33a; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.run
    ADD CONSTRAINT "FK_c0e8aa62541a592554607dea33a" FOREIGN KEY (period_id) REFERENCES public.period(id);


--
-- Name: run FK_c19e1cb7a550cc4e3b5acc7e242; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.run
    ADD CONSTRAINT "FK_c19e1cb7a550cc4e3b5acc7e242" FOREIGN KEY (market_id) REFERENCES public.market(id);


--
-- Name: userbalance FK_c850d8f72c4ef331ab206ac09c2; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userbalance
    ADD CONSTRAINT "FK_c850d8f72c4ef331ab206ac09c2" FOREIGN KEY (exchange_id) REFERENCES public.exchange(id);


--
-- Name: userfees FK_cae3dd203f9deb573bb8b2785f3; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userfees
    ADD CONSTRAINT "FK_cae3dd203f9deb573bb8b2785f3" FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: usernonce FK_cd86165abcb20c7ab712bedc380; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.usernonce
    ADD CONSTRAINT "FK_cd86165abcb20c7ab712bedc380" FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: exchange_periods_period FK_d85d0dad66f034e63ee1ecbfa98; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.exchange_periods_period
    ADD CONSTRAINT "FK_d85d0dad66f034e63ee1ecbfa98" FOREIGN KEY ("periodId") REFERENCES public.period(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: userbalance FK_ed93a8fa9a3a7b8486c20a3aa3f; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.userbalance
    ADD CONSTRAINT "FK_ed93a8fa9a3a7b8486c20a3aa3f" FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: news FK_f2f642257084b8c00e0c270f5e6; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.news
    ADD CONSTRAINT "FK_f2f642257084b8c00e0c270f5e6" FOREIGN KEY (owner_id) REFERENCES public."user"(id);


--
-- Name: runsetting FK_f60f26a4bdfce7d6c54b4cd7983; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.runsetting
    ADD CONSTRAINT "FK_f60f26a4bdfce7d6c54b4cd7983" FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: period_exchanges_exchange FK_f6472a151197e6bb0ca51ee6442; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.period_exchanges_exchange
    ADD CONSTRAINT "FK_f6472a151197e6bb0ca51ee6442" FOREIGN KEY ("periodId") REFERENCES public.period(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: market FK_f6b357fc0b9185466896e001bd1; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.market
    ADD CONSTRAINT "FK_f6b357fc0b9185466896e001bd1" FOREIGN KEY (exchange_id) REFERENCES public.exchange(id);


--
-- Name: referral FK_fa62b77aca6a1338d29e3d61e1e; Type: FK CONSTRAINT; Schema: public; Owner: twats
--

ALTER TABLE ONLY public.referral
    ADD CONSTRAINT "FK_fa62b77aca6a1338d29e3d61e1e" FOREIGN KEY (referrer) REFERENCES public."user"(id);


--
-- PostgreSQL database dump complete
--

