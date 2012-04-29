<?php

namespace apacheLogParser;

class ApacheLogRecordTest extends \PHPUnit_Framework_TestCase{
    public function testAddLoggedValue(){
        $log = new ApacheLogRecord();
        $this->assertEquals('',$log->getRemoteIP());
        $log->logValue('remoteIP', '127.0.0.1');
        $this->assertEquals('127.0.0.1',$log->getRemoteIP());
        return $log;
    }
    
    /**
     * @depends testAddLoggedValue
     */
    public function testAddIntegerLoggedValue(ApacheLogRecord $log){
        $log->logValue('port', 80);
        $this->assertEquals(80,$log->getPort());
        $this->assertTrue(is_int($log->getPort()));
    }
    
    /**
     * @depends testAddLoggedValue
     */
    public function testAddIntegerRespBytes(ApacheLogRecord $log){
        $log->logValue('respBytes', 80);
        $this->assertEquals(80,$log->getRespBytes());
        $this->assertTrue(is_int($log->getRespBytes()));
        return $log;
    }
    
    /**
     * @depends testAddIntegerRespBytes
     */
    public function testAddDashRespBytes(ApacheLogRecord $log){
        $log->logValue('respBytes', '-');
        $this->assertEquals(0,$log->getRespBytes());
        $this->assertTrue(is_int($log->getRespBytes()));
    }
    
    /**
     * @depends testAddLoggedValue
     */
    public function testAddValidReqTime(ApacheLogRecord $log){
        $log->logValue('reqTime', '18/Mar/2012:00:29:10 -0500');
        $this->assertEquals('DateTime',get_class($log->getReqTime()));
        $this->assertEquals('18',$log->getReqTime()->format('d'));
        $this->assertEquals('03',$log->getReqTime()->format('m'));
        $this->assertEquals('2012',$log->getReqTime()->format('Y'));
        $this->assertEquals('00',$log->getReqTime()->format('H'));
        $this->assertEquals('29',$log->getReqTime()->format('i'));
        $this->assertEquals('10',$log->getReqTime()->format('s'));
    }
    
    /**
     * @depends testAddLoggedValue
     */
    public function testSetCompleteConnStatus(ApacheLogRecord $log){
        $log->logValue('completeConnStatus', 'X');
        $this->assertEquals('aborted',$log->getCompleteConnStatus());
        $log->logValue('completeConnStatus', '+');
        $this->assertEquals('keep-alive',$log->getCompleteConnStatus());
        $log->logValue('completeConnStatus', '-');
        $this->assertEquals('closed',$log->getCompleteConnStatus());
    }
    
    /**
     * @depends testAddLoggedValue
     */
    public function testSetRequestHeader(ApacheLogRecord $log){
        $log->logValue('reqHeader:Referer', 
                'http://www.w3.org/hypertext/DataSources/Overview.html');
        $this->assertEquals(1,count($log->getReqHeader()));
        $this->assertEquals('http://www.w3.org/hypertext/DataSources/Overview.html',
                $log->getReqHeader('Referer'));
        return $log;
    }
    
    /**
     * @depends testSetRequestHeader
     */
    public function testOverwriteRequestHeader(ApacheLogRecord $log){
        $log->logValue('reqHeader:Referer', 
                'http://www.w3.org/Protocols/HTTP/HTRQ_Headers.html');
        $this->assertEquals(1,count($log->getReqHeader()));
        $this->assertEquals('http://www.w3.org/Protocols/HTTP/HTRQ_Headers.html',
                $log->getReqHeader('Referer'));
        return $log;
    }
    
    /**
     * @depends testSetRequestHeader
     */
    public function testSetTwoRequestHeader(ApacheLogRecord $log){
        $log->logValue('reqHeader:User-agent', 'Mozilla/4.08 [en] (Win98; I ;Nav)');
        $this->assertEquals(2,count($log->getReqHeader()));
        $this->assertEquals('http://www.w3.org/hypertext/DataSources/Overview.html',
                $log->getReqHeader('Referer'));
        $this->assertEquals('Mozilla/4.08 [en] (Win98; I ;Nav)',
                $log->getReqHeader('User-agent'));
        return $log;
    }

    /**
     * Same test as for RequestHeader, but different variable
     * @depends testSetTwoRequestHeader
     */
    public function testSetCookie(ApacheLogRecord $log){
        $log->logValue('cookie:foo', 'bar');
        $this->assertEquals(1,count($log->getCookie()));
        $this->assertEquals('bar', $log->getCookie('foo'));
        //makes sure the other variable isn't overwritten
        $this->assertEquals('Mozilla/4.08 [en] (Win98; I ;Nav)',
                $log->getReqHeader('User-agent'));
        return $log;
    }
    
    /**
     * Same test as for RequestHeader, but different variable
     * @depends testSetCookie
     */
    public function testSetEnvironment(ApacheLogRecord $log){
        $log->logValue('environment:foo', 'baz');
        $this->assertEquals(1,count($log->getEnvironment()));
        $this->assertEquals('baz', $log->getEnvironment('foo'));
        //makes sure the other variable isn't overwritten
        $this->assertEquals('bar', $log->getCookie('foo'));
        return $log;
    }
    
    /**
     * Same test as for RequestHeader, but different variable
     * @depends testSetCookie
     */
    public function testSetRespHeader(ApacheLogRecord $log){
        $log->logValue('respHeader:Server', 'Apache/2.4.1 (Unix) OpenSSL/1.0.0g');
        $this->assertEquals(1,count($log->getRespHeader()));
        $this->assertEquals('Apache/2.4.1 (Unix) OpenSSL/1.0.0g',
                $log->getRespHeader('Server'));
        return $log;
    }
    
    /**
     * Same test as for RequestHeader, but different variable
     * @depends testSetCookie
     */
    public function testSetModule(ApacheLogRecord $log){
        $log->logValue('module:foo', 'bar');
        $this->assertEquals(1,count($log->getModule()));
        $this->assertEquals('bar', $log->getModule('foo'));
        return $log;
    }
    
    /**
     * @depends testSetRequestHeader
     * @expectedException \InvalidArgumentException
     */
    public function testSetInvalidArrayVariable(ApacheLogRecord $log){
        $log->logValue('doesntExist:foo', 'bar');
    }
    
    /**
     * @depends testSetRequestHeader
     */
    public function testSetInvalidVariable(ApacheLogRecord $log){
        try {
            $log->logValue('doesntExist', 'bar');
        }
        catch (\InvalidArgumentException $expected) {
            return $log;
        }
 
        $this->fail('An expected exception has not been raised.');
    }
    
    /**
     * @depends testSetInvalidVariable
     * @expectedException \InvalidArgumentException
     */
    public function testGetInvalidVariable(ApacheLogRecord $log){
        $this->markTestSkipped('Tests deprecated functionality');
        $test = $log->doesntExist;
    }
    
    /**
     * @depends testSetRequestHeader
     * @expectedException \InvalidArgumentException
     */
    public function testGetInvalidReqHeader(ApacheLogRecord $log){
        $test = $log->getReqHeader('notSet');
    }
    
    /**
     * @depends testSetCookie
     * @expectedException \InvalidArgumentException
     */
    public function testGetInvalidCookie(ApacheLogRecord $log){
        $test = $log->getCookie('notSet');
    }
    
    /**
     * @depends testSetEnvironment
     * @expectedException \InvalidArgumentException
     */
    public function testGetInvalidEnvironment(ApacheLogRecord $log){
        $test = $log->getEnvironment('notSet');
    }
    
    /**
     * @depends testSetRespHeader
     * @expectedException \InvalidArgumentException
     */
    public function testGetInvalidRespHeader(ApacheLogRecord $log){
        $test = $log->getRespHeader('notSet');
    }
    
    /**
     * @depends testSetModule
     * @expectedException \InvalidArgumentException
     */
    public function testGetInvalidModule(ApacheLogRecord $log){
        $test = $log->getModule('notSet');
    }
    
}
?>
