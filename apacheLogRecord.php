<?php
namespace apacheLogParser;

class ApacheLogRecord{
    /**
     * Remote IP-address
     * @var string
     */
    protected $remoteIP='';
    /**
     * Local IP-address
     * @var string
     */
    protected $localIP='';
    /**
     * Size of response in bytes, excluding HTTP headers.
     * @var int
     */
    protected $respBytes=0;
    /**
     * The contents of cookies in the request sent to the server.
     * @var array[string]string
     */
    protected $cookie=array();
    /**
     * The time taken to serve the request, in microseconds.
     * @var int
     */
    protected $respMicro=0;
    /**
     * The contents of environment variables
     * @var array[string]string 
     */
    protected $environment=array();
    /**
     * Filename
     * @var string
     */
    protected $filename='';
    /**
     * Remote host
     * @var string
     */
    protected $clientIP='';
    /**
     * The request protocol
     * @var string
     */
    protected $protocol='';
    /**
     * The contents of header line(s) in the request sent to the server.
     * Changes made by other modules (e.g. mod_headers) affect this.
     * @var array[string]string
     */
    protected $reqHeader=array();
    /**
     * Remote logname (from identd, if supplied). This will return a dash 
     * unless IdentityCheck is set On.
     * @var string
     */
    protected $remoteLogname='';
    /**
     * The request method
     * @var string
     */
    protected $reqMethod='';
    /**
     * The contents of notes from other modules.
     * @var array[string]string
     */
    protected $module=array();
    /**
     * The contents of header line(s) in the reply.
     * @var array[string]string
     */
    protected $respHeader=array();
    /**
     * The canonical port of the server serving the request
     * @var int
     */
    protected $port=0;
    /**
     * The process ID of the child that serviced the request.
     * @var int
     */
    protected $pid=0;
    /**
     * The thread id of the child that serviced the request.
     * @var int
     */
    protected $tid=0;
    /**
     * The query string (prepended with a ? if a query string exists, 
     * otherwise an empty string)
     * @var string
     */
    protected $queryString='';
    /**
     * First line of request
     * @var string
     */
    protected $request='';
    /**
     * Status. 
     * For requests that got internally redirected, 
     * this is the status of the last request
     * @var int
     */
    protected $lastStatus=0;
    /**
     * Status. 
     * For requests that got internally redirected, 
     * this is the status of the original request
     * @var int
     */
    protected $firstStatus=0;
    /**
     * Time the request was received 
     * @var DateTime
     */
    protected $reqTime=null;
    /**
     * The time taken to serve the request, in seconds.
     * @var int
     */
    protected $respSec=0;
    /**
     * Remote user (from auth; may be bogus if return status (%s) is 401)
     * @var string
     */
    protected $user='';
    /**
     * The URL path requested, not including any query string.
     * @var string
     */
    protected $url='';
    /**
     * The canonical ServerName of the server serving the request.
     * @var string
     */
    protected $serverName='';
    /**
     * The server name according to the UseCanonicalName setting.
     * @var string
     */
    protected $useCanonicalServerName='';
    /**
     * Connection status when response is completed
     * One of "aborted","keep-alive","closed"
     * @var string
     */
    protected $completeConnStatus;
    /**
     * Bytes received, including request and headers, cannot be zero. 
     * You need to enable mod_logio to use this.
     * @var int
     */
    protected $libIOBytesIn=0;
    /**
     * Bytes sent, including headers, cannot be zero. 
     * You need to enable mod_logio to use this.
     * @var int
     */
    protected $libIOBytesOut=0;
    
    /**
     * Stores a parsed Apache log directive appropriately
     * 
     * @param string $logVariable
     * @param string $value 
     * 
     * @return void
     * 
     * @throws InvalidArgumentException If the logVariable is not a valid variable
     */
    public function logValue($logVariable,$value){
        $intOpts = array('respMicro','lastStatus','firstStatus',
            'respSec','libIOBytesIn','libIOBytesOut');
        $specOpts = array('respBytes','reqTime','completeConnStatus');
        
        if(in_array($logVariable,$intOpts)){$this->$logVariable=(int)$value;}
        elseif(in_array($logVariable,$specOpts)){
            switch($logVariable){
                case 'respBytes':
                    if($value=='-'){$this->respBytes=0;}
                    else{$this->respBytes=(int)$value;}
                    break;
                case 'reqTime':
                    $this->reqTime = new \DateTime($value);
                    break;
                case 'completeConnStatus':
                    $trans = array('X'=>"aborted",'+'=>"keep-alive",'-'=>"closed");
                    $this->completeConnStatus = $trans[$value];
                    break;
            }
        }
        elseif(strpos($logVariable, ':')!==false){
            $varName = strtok($logVariable, ':');
            $varKey = strtok(':');
            if(!isset($this->$varName)){
                throw new \InvalidArgumentException('This property can not be logged');
            }
            //directly setting it is not working (__get is in the way?)
            $this->$varName=array_merge($this->$varName,array($varKey=>$value));
        }
        else{
            if(!isset($this->$logVariable)){
                throw new \InvalidArgumentException('This property can not be logged');
            }
            $this->$logVariable = $value;
        }
    }
    
    /**
     * Gets a log variable
     * 
     * @param string $varName 
     * @return mixed 
     * 
     * @throws InvalidArgumentException If the requested variable doesn't exist
     * @deprecated
     */
    public function __get($varName){
        error_log('This function is deprecated and will be removed in later versions', 
                E_USER_DEPRECATED);
        if(!isset($this->$varName)){
            throw new \InvalidArgumentException('This property('.$varName.') does not exist');
        }
        return $this->$varName;
    }
    
    /**
     * Gets a logged cookie value
     * If there is no $pos set, the function will return all the cookies
     * 
     * @param string $pos [Optional]The cookie to be looked up
     * @return string | array[string]string
     * 
     * @throws InvalidArgumentException If the value doesn't exist
     */
    public function getCookie($pos=-1){
        if($pos===-1){return $this->cookie;}
        if(isset($this->cookie[$pos])){return $this->cookie[$pos];}
        else{throw new \InvalidArgumentException('This property does not exist');}
    }

    /**
     * Gets a logged environment variable value
     * If there is no $pos set, the function will return all the environment vars
     * 
     * @param string $pos [Optional]The environment variable to be looked up
     * @return string | array[string]string
     * 
     * @throws InvalidArgumentException If the value doesn't exist
     */
    public function getEnvironment($pos=-1){
        if($pos===-1){return $this->environment;}
        if(isset($this->environment[$pos])){return $this->environment[$pos];}
        else{throw new \InvalidArgumentException('This property does not exist');}
    }

    /**
     * Gets a logged request header value
     * If there is no $pos set, the function will return all the headers
     * 
     * @param string $pos [Optional]The request header to be looked up
     * @return string | array[string]string
     * 
     * @throws InvalidArgumentException If the value doesn't exist
     */
    public function getReqHeader($pos=-1){
        if($pos===-1){return $this->reqHeader;}
        if(isset($this->reqHeader[$pos])){return $this->reqHeader[$pos];}
        else{throw new \InvalidArgumentException('This property does not exist');}
    }

    /**
     * Gets a logged module value
     * If there is no $pos set, the function will return all the module values
     * 
     * @param string $pos [Optional]The module to be looked up
     * @return string |array[string]string
     * 
     * @throws InvalidArgumentException If the value doesn't exist
     */
    public function getModule($pos=-1){
        if($pos===-1){return $this->module;}
        if(isset($this->module[$pos])){return $this->module[$pos];}
        else{throw new \InvalidArgumentException('This property does not exist');}
    }

    /**
     * Gets a logged response header value
     * If there is no $pos set, the function will return all the headers
     * 
     * @param string $pos The response header to be looked up
     * @return string 
     * 
     * @throws InvalidArgumentException If the value doesn't exist
     */
    public function getRespHeader($pos=-1){
        if($pos===-1){return $this->respHeader;}
        if(isset($this->respHeader[$pos])){return $this->respHeader[$pos];}
        else{throw new \InvalidArgumentException('This property does not exist');}
    }
    
    /**
     * Remote IP-address
     * @return string
     */
    public function getRemoteIP(){
        return $this->remoteIP;
    }
    
    /**
     * Local IP-address
     * @return string
     */
    public function getLocalIP(){
        return $this->localIP;
    }
    /**
     * Size of response in bytes, excluding HTTP headers.
     * @return int
     */
    public function getRespBytes(){
        return $this->respBytes;
    }
    /**
     * The time taken to serve the request, in microseconds.
     * @return int
     */
    public function getRespMicro(){
        return $this->respMicro;
    }
    /**
     * Filename
     * @return string
     */
    public function getFilename(){
        return $this->filename;
    }
    /**
     * Remote host
     * @return string
     */
    public function getClientIP(){
        return $this->clientIP;
    }
    /**
     * The request protocol
     * @return string
     */
    public function getProtocol(){
        return $this->protocol;
    }
    /**
     * Remote logname (from identd, if supplied). This will return a dash 
     * unless IdentityCheck is set On.
     * @return string
     */
    public function getRemoteLogname(){
        return $this->remoteLogname;
    }
    /**
     * The request method
     * @return  string
     */
    public function getReqMethod(){
        return $this->reqMethod;
    }
    /**
     * The canonical port of the server serving the request
     * @return int
     */
    public function getPort(){
        return $this->port;
    }
    /**
     * The process ID of the child that serviced the request.
     * @return int
     */
    public function getPid(){
        return $this->pid;
    }
    /**
     * The thread id of the child that serviced the request.
     * @return int
     */
    public function getTid(){
        return $this->tid;
    }
    /**
     * The query string (prepended with a ? if a query string exists, 
     * otherwise an empty string)
     * @return string
     */
    public function getQueryString(){
        return $this->queryString;
    }
    /**
     * First line of request
     * @return string
     */
    public function getRequest(){
        return $this->request;
    }
    /**
     * Status. 
     * For requests that got internally redirected, 
     * this is the status of the last request
     * @return int
     */
    public function getLastStatus(){
        return $this->lastStatus;
    }
    /**
     * Status. 
     * For requests that got internally redirected, 
     * this is the status of the original request
     * @return int
     */
    public function getFirstStatus(){
        return $this->firstStatus;
    }
    /**
     * Time the request was received 
     * @return DateTime
     */
    public function getReqTime(){
        return $this->reqTime;
    }
    /**
     * The time taken to serve the request, in seconds.
     * @return int
     */
    public function getRespSec(){
        return $this->respSec;
    }
    /**
     * Remote user (from auth; may be bogus if return status (%s) is 401)
     * @return string
     */
    public function getUser(){
        return $this->user;
    }
    /**
     * The URL path requested, not including any query string.
     * @return string
     */
    public function getUrl(){
        return $this->url;
    }
    /**
     * The canonical ServerName of the server serving the request.
     * @return string
     */
    public function getServerName(){
        return $this->serverName;
    }
    /**
     * The server name according to the UseCanonicalName setting.
     * @return string
     */
    public function getUseCanonicalServerName(){
        return $this->useCanonicalServerName;
    }
    /**
     * Connection status when response is completed
     * One of "aborted","keep-alive","closed"
     * @return string
     */
    public function getCompleteConnStatus(){
        return $this->completeConnStatus;
    }
    /**
     * Bytes received, including request and headers, cannot be zero. 
     * You need to enable mod_logio to use this.
     * @return int
     */
    public function getLibIOBytesIn(){
        return $this->libIOBytesIn;
    }
    /**
     * Bytes sent, including headers, cannot be zero. 
     * You need to enable mod_logio to use this.
     * @return int
     */
    public function getLibIOBytesOut(){
        return $this->libIOBytesOut;
    }
}
?>
